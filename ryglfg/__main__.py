# Module docstring
"""
This module contains the main :mod:`ryglfg` server.
"""

# Special imports
from __future__ import annotations
import typing as t

# External imports
import logging
import uvicorn
import threading
import datetime
import fastapi as f
import fastapi.middleware.cors as cors
import sqlalchemy.orm as so
import sqlalchemy.sql as ss
import requests

# Internal imports
from . import globals
from . import database
from . import models
from . import auth

# Special global objects
log = logging.getLogger(__name__)
config = globals.lazy_config.evaluate()
app = f.FastAPI(
    title="RYGlfg",
    description='The "Looking For Group" service of the RYG community',
    version="1.0.0",
)
app.add_middleware(
    cors.CORSMiddleware,
    allow_origins=config["api.allow_origins"],
    allow_methods=["*"],
    allow_headers=["*"],
)
CurrentUser = auth.Auth0CustomUser(domain=config["authzero.domain"])
planned_event = threading.Event()
open_event = threading.Event()


# Waiter threads
def planned_event_manager():
    log.info("Starting planned event manager...")
    Session = database.lazy_Session.evaluate()
    while True:
        with Session(future=True) as session:
            lfg = session.execute(
                ss.select(database.Announcement)
                  .where(database.Announcement.state == database.AnnouncementState.PLANNED)
                  .order_by(database.Announcement.opening_time)
            ).scalar()
            if lfg is not None:
                aid = lfg.aid
                timeout = (lfg.opening_time - datetime.datetime.now()).total_seconds()
            else:
                aid = None
                timeout = None

        try:
            if timeout is not None and timeout < 0:
                raise TimeoutError()
            planned_event.wait(timeout=timeout)
        except TimeoutError:
            with Session(future=True) as session:
                lfg = session.execute(
                    ss.select(database.Announcement)
                      .where(database.Announcement.aid == aid)
                ).scalar()
                lfg.state = database.AnnouncementState.OPEN
                session.commit()

                open_event.set()

                for webhook in session.execute(ss.select(database.Webhook)).scalars():
                    requests.post(webhook.url, data=models.EventAnnouncement(
                        type="open",
                        announcement=models.AnnouncementFull.from_orm(lfg),
                    ).json())
        else:
            planned_event.clear()


def open_event_manager():
    log.info("Starting open event manager...")
    Session = database.lazy_Session.evaluate()
    while True:
        with Session(future=True) as session:
            lfg = session.execute(
                ss.select(database.Announcement)
                  .where(database.Announcement.state == database.AnnouncementState.OPEN)
                  .order_by(database.Announcement.opening_time)
            ).scalar()
            if lfg is not None:
                aid = lfg.aid
                timeout = (lfg.autostart_time - datetime.datetime.now()).total_seconds()
            else:
                aid = None
                timeout = None

        try:
            if timeout is not None and timeout < 0:
                raise TimeoutError()
            open_event.wait(timeout=timeout)
        except TimeoutError:
            with Session(future=True) as session:
                lfg = session.execute(
                    ss.select(database.Announcement)
                      .where(database.Announcement.aid == aid)
                ).scalar()
                lfg.state = database.AnnouncementState.STARTED
                lfg.closure_time = datetime.datetime.now()
                session.commit()

                for webhook in session.execute(ss.select(database.Webhook)).scalars():
                    requests.post(webhook.url, data=models.EventAnnouncement(
                        type="autostart",
                        announcement=models.AnnouncementFull.from_orm(lfg),
                    ).json())
        else:
            open_event.clear()


# API routes
@app.get(
    "/auth",
    summary="Check your user status.",
    response_model=auth.Auth0CustomClaims,
    tags=["Authorization"],
)
def auth_get(
        *,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser)
):
    """
    Decode and verify the signature of your current JWT, returning its contents.
    """
    return cu


@app.get(
    "/lfg",
    summary="Get all LFGs.",
    response_model=t.List[models.AnnouncementFull],
    tags=["LFGs"],
)
def lfg_get(
        *,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        session: so.Session = f.Depends(database.DatabaseSession),

        limit: int = f.Query(
            50, description="The number of LFGs that will be returned.", ge=0, le=500
        ),
        offset: int = f.Query(
            0, description="Start returning LFGs from this offset.", ge=0
        ),
        filter_state: t.Optional[database.AnnouncementState] = f.Query(
            None, description="Get only LFGs in the specified state."
        ),
):
    """
    Return all LFGs sorted starting by the earliest autostart time.

    Requires the `read:lfg` scope.
    """
    if "read:lfg" not in cu.permissions:
        raise f.HTTPException(403, "Missing `read:lfg` scope.")

    query = ss.select(database.Announcement)
    query = query.where(database.Announcement.state == filter_state) if filter_state is not None else query
    query = query.offset(offset)
    query = query.limit(limit)
    query = query.order_by(database.Announcement.autostart_time)
    results = session.execute(query)
    return list(results.scalars())


@app.post(
    "/lfg",
    summary="Post a new LFG.",
    response_model=models.AnnouncementFull,
    tags=["LFGs"]
)
def lfg_post(
        *,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        session: so.Session = f.Depends(database.DatabaseSession),
        user: t.Optional[str] = f.Query(None, description="The user on behalf of which you are acting."),
        data: models.AnnouncementEditable = f.Body(..., description="The data of the LFG you are creating."),
):
    """
    Create a new LFG with the passed data.

    Requires the `create:lfg` scope, or the `create:lfg_sudo` scope if you're creating a LFG on behalf of another user.
    """
    if "create:lfg" not in cu.permissions:
        raise f.HTTPException(403, "Missing `create:lfg` scope.")

    if user is None:
        user = cu.sub

    if "create:lfg_sudo" not in cu.permissions and user != cu.sub:
        raise f.HTTPException(403, "Missing `create:lfg_sudo` scope.")

    # noinspection PyArgumentList
    lfg = database.Announcement(**data.dict(), creator_id=user)
    session.add(lfg)
    session.commit()

    planned_event.set()

    for webhook in session.execute(ss.select(database.Webhook)).scalars():
        requests.post(webhook.url, data=models.EventAnnouncement(
            type="create",
            announcement=models.AnnouncementFull.from_orm(lfg),
        ).json())

    return lfg


@app.get(
    "/lfg/{aid}",
    summary="Get info about a specific LFG.",
    response_model=models.AnnouncementFull,
    tags=["LFGs"]
)
def lfg_get_single(
        *,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        session: so.Session = f.Depends(database.DatabaseSession),
        aid: int = f.Path(..., description="The aid of the LFG to retrieve."),
):
    """
    Return the requested LFG.

    Requires the `read:lfg` scope.
    """
    if "read:lfg" not in cu.permissions:
        raise f.HTTPException(403, "Missing `read:lfg` scope.")

    lfg = session.execute(
        ss.select(database.Announcement).where(database.Announcement.aid == aid)
    ).scalar()

    if lfg is None:
        raise f.HTTPException(404, "No such LFG.")
    return lfg


@app.put(
    "/lfg/{aid}",
    summary="Edit a LFG.",
    response_model=models.AnnouncementFull,
    tags=["LFGs"]
)
def lfg_put(
        *,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        session: so.Session = f.Depends(database.DatabaseSession),
        aid: int = f.Path(..., description="The aid of the LFG to edit."),
        data: models.AnnouncementEditable = f.Body(..., description="The new data of the LFG.")
):
    """
    Set the data of the specified LFG to the request body.

    Requires the `edit:lfg` scope.

    If you're trying to edit a LFG you're not the creator of, additionally requires the `edit:lfg_sudo` scope.

    If you're trying to edit a started or cancelled LFG, additionally requires the `edit:lfg_admin` scope.
    """
    if "edit:lfg" not in cu.permissions:
        raise f.HTTPException(403, "Missing `edit:lfg` scope.")

    lfg = session.execute(
        ss.select(database.Announcement).where(database.Announcement.aid == aid)
    ).scalar()

    if lfg is None:
        raise f.HTTPException(404, "No such LFG.")

    if lfg.creator_id != cu.sub and "edit:lfg_sudo" not in cu.permissions:
        raise f.HTTPException(403, "Missing `edit:lfg_sudo` scope.")

    if lfg.state > database.AnnouncementState.OPEN and "edit:lfg_admin" not in cu.permissions:
        raise f.HTTPException(403, "Missing `edit:lfg_admin` scope.")

    lfg.update(**data.dict())
    session.commit()

    if lfg.state == database.AnnouncementState.PLANNED:
        planned_event.set()
    elif lfg.state == database.AnnouncementState.OPEN:
        open_event.set()

    return lfg


@app.delete(
    "/lfg/{aid}",
    summary="Quietly delete a LFG.",
    status_code=204,
    tags=["LFGs"]
)
def lfg_delete(
        *,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        session: so.Session = f.Depends(database.DatabaseSession),
        aid: int = f.Path(..., description="The aid of the LFG to delete."),
):
    """
    Quietly delete a LFG without triggering any webhook or notification.

    Follows the `DELETE` specification: it will return a success even if the LFG does not exist.

    Requires the `delete:lfg_admin` scope.
    """
    if "delete:lfg_admin" not in cu.permissions:
        raise f.HTTPException(403, "Missing `delete:lfg_admin` scope.")

    lfg = session.execute(
        ss.select(database.Announcement).where(database.Announcement.aid == aid)
    ).scalar()

    if lfg is not None:
        session.delete(lfg)
        session.commit()

    if lfg.state == database.AnnouncementState.PLANNED:
        planned_event.set()
    elif lfg.state == database.AnnouncementState.OPEN:
        open_event.set()

    return f.Response(status_code=204)


@app.patch(
    "/lfg/{aid}/start",
    summary="Start a LFG.",
    response_model=models.AnnouncementFull,
    tags=["LFGs"],
)
def lfg_start(
        *,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        session: so.Session = f.Depends(database.DatabaseSession),

        aid: int = f.Path(..., description="The id of the LFG that you want to start."),
        user: t.Optional[str] = f.Query(None, description="The id of the user you are acting on behalf of."),
):
    """
    Start a LFG, sending notifications via the webhooks.

    Requires the `start:lfg` scope.

    Additionally requires the `start:lfg_sudo` if you're acting on behalf of another user.

    Additionally requires the `start:lfg_admin` if you're trying to start another user's LFG.
    """
    if "start:lfg" not in cu.permissions:
        raise f.HTTPException(403, "Missing `start:lfg` scope.")

    if user is None:
        user = cu.sub

    if "start:lfg_sudo" not in cu.permissions and user != cu.sub:
        raise f.HTTPException(403, "Missing `start:lfg_sudo` scope.")

    lfg = session.execute(
        ss.select(database.Announcement).where(database.Announcement.aid == aid)
    ).scalar()

    if lfg is None:
        raise f.HTTPException(404, "No such LFG.")

    if "start:lfg_admin" not in cu.permissions and user != lfg.creator_id:
        raise f.HTTPException(403, "Missing `start:lfg_admin` scope.")

    if lfg.state != database.AnnouncementState.OPEN:
        raise f.HTTPException(409, "LFG is not in the `OPEN` state.")

    lfg.state = database.AnnouncementState.STARTED
    lfg.closure_time = datetime.datetime.now()
    lfg.closure_id = user

    session.commit()

    for webhook in session.execute(ss.select(database.Webhook)).scalars():
        requests.post(webhook.url, data=models.EventAnnouncement(
            type="start",
            announcement=models.AnnouncementFull.from_orm(lfg),
        ).json())

    return lfg


@app.patch(
    "/lfg/{aid}/cancel",
    summary="Cancel a LFG.",
    response_model=models.AnnouncementFull,
    tags=["LFGs"],
)
def lfg_cancel(
        *,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        session: so.Session = f.Depends(database.DatabaseSession),

        aid: int = f.Path(..., description="The id of the LFG that you want to cancel."),
        user: t.Optional[str] = f.Query(None, description="The id of the user you are acting on behalf of."),
):
    """
    Cancel a LFG, sending notifications via the webhooks.

    Requires the `cancel:lfg` scope.

    Additionally requires the `cancel:lfg_sudo` if you're acting on behalf of another user.

    Additionally requires the `cancel:lfg_admin` if you're trying to start another user's LFG.
    """
    if "cancel:lfg" not in cu.permissions:
        raise f.HTTPException(403, "Missing `cancel:lfg` scope.")

    if user is None:
        user = cu.sub

    if "cancel:lfg_sudo" not in cu.permissions and user != cu.sub:
        raise f.HTTPException(403, "Missing `cancel:lfg_sudo` scope.")

    lfg = session.execute(
        ss.select(database.Announcement).where(database.Announcement.aid == aid)
    ).scalar()

    if lfg is None:
        raise f.HTTPException(404, "No such LFG.")

    if "cancel:lfg_admin" not in cu.permissions and user != lfg.creator_id:
        raise f.HTTPException(403, "Missing `cancel:lfg_admin` scope.")

    if lfg.state > database.AnnouncementState.OPEN:
        raise f.HTTPException(409, "LFG has already closed.")

    lfg.state = database.AnnouncementState.CANCELLED
    lfg.closure_time = datetime.datetime.now()
    lfg.closure_id = user

    session.commit()

    for webhook in session.execute(ss.select(database.Webhook)).scalars():
        requests.post(webhook.url, data=models.EventAnnouncement(
            type="cancel",
            announcement=models.AnnouncementFull.from_orm(lfg),
        ).json())

    return lfg


@app.put(
    "/lfg/{aid}/answer",
    summary="Answer an open LFG.",
    response_model=models.ResponseFull,
    tags=["Responses"],
)
def lfg_answer_put(
        *,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        session: so.Session = f.Depends(database.DatabaseSession),
        fr: f.Response,

        aid: int = f.Path(..., description="The id of the LFG that should be answered."),
        user: t.Optional[str] = f.Query(None, description="The id of the user you are answering on behalf of."),
        data: models.ResponseEditable = f.Body(..., description="The data of the response."),
):
    """
    Respond to a LFG, or edit the response if it had already been sent, sending notifications via the webhooks.

    Requires the `answer:lfg` scope.

    Additionally requires the `answer:lfg_sudo` scope if you are answering on behalf of another user.
    """
    if "answer:lfg" not in cu.permissions:
        raise f.HTTPException(403, "Missing `answer:lfg` scope.")

    if user is None:
        user = cu.sub

    if "answer:lfg_sudo" not in cu.permissions and user != cu.sub:
        raise f.HTTPException(403, "Missing `answer:lfg_sudo` scope.")

    response = session.execute(
        ss.select(database.Response).where(
            ss.and_(
                database.Response.aid == aid,
                database.Response.partecipant_id == cu.sub,
            )
        )
    ).scalar()

    if response is None:
        # noinspection PyArgumentList
        response = database.Response(**data.dict(), aid=aid, partecipant_id=user)
        session.add(response)
        fr.status_code = 201
    else:
        response.update(**data.dict())
        fr.status_code = 200

    session.commit()

    for webhook in session.execute(ss.select(database.Webhook)).scalars():
        requests.post(webhook.url, data=models.EventResponse(
            type="answer",
            code=fr.status_code,
            response=models.ResponseFull.from_orm(response),
        ).json())

    return response


@app.get(
    "/webhook",
    summary="Get all configured webhooks.",
    response_model=t.List[models.WebhookFull],
    tags=["Webhooks"],
)
def webhooks_get(
        *,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        session: so.Session = f.Depends(database.DatabaseSession),
):
    """
    Return a list of all configured webhooks.

    Requires the `read:webhooks` scope.
    """
    if "read:webhooks" not in cu.permissions:
        raise f.HTTPException(403, "Missing `read:webhooks` scope.")

    results = session.execute(
        ss.select(database.Webhook)
    ).scalars()

    return list(results)


@app.post(
    "/webhook",
    summary="Create a new webhook.",
    response_model=models.WebhookFull,
    tags=["Webhooks"],
)
def webhooks_post(
        *,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        session: so.Session = f.Depends(database.DatabaseSession),

        data: models.WebhookEditable = f.Body(..., description="The data that the created webhook should have.")
):
    """
    Create a new webhook.

    Only a single format is currently supported:

    - `ryglfg` sends data in a custom JSON format

    Requires the `create:webhooks` scope.
    """
    if "create:webhooks" not in cu.permissions:
        raise f.HTTPException(403, "Missing `create:webhooks` scope.")

    # noinspection PyArgumentList
    webhook = database.Webhook(**data.dict())
    session.add(webhook)
    session.commit()
    return webhook


@app.delete(
    "/webhook/{wid}",
    summary="Delete a webhook.",
    status_code=204,
    tags=["Webhooks"],
)
def webhooks_delete(
        *,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        session: so.Session = f.Depends(database.DatabaseSession),

        wid: int = f.Path(..., description="The id of the webhook to delete."),
):
    """
    Delete a specific webhook.

    Requires the `delete:webhooks` scope.
    """
    if "delete:webhooks" not in cu.permissions:
        raise f.HTTPException(403, "Missing `delete:webhooks` scope.")

    webhook = session.execute(
        ss.select(database.Webhook).where(database.Webhook.wid == wid)
    ).scalar()

    if webhook is None:
        raise f.HTTPException(404, "No such webhook.")

    session.delete(webhook)
    session.commit()
    return f.Response(status_code=204)


@app.post(
    "/webhook/{wid}/test",
    summary="Test a webhook.",
    status_code=204,
    tags=["Webhooks"],
)
def webhooks_test(
        *,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        session: so.Session = f.Depends(database.DatabaseSession),

        wid: int = f.Path(..., description="The id of the webhook to delete."),
):
    """
    Send test data to a webhook.

    Requires the `test:webhooks` scope.
    """
    if "test:webhooks" not in cu.permissions:
        raise f.HTTPException(403, "Missing `test:webhooks` scope.")

    webhook = session.execute(
        ss.select(database.Webhook).where(database.Webhook.wid == wid)
    ).scalar()

    if webhook.format == database.WebhookFormat.RYGLFG:
        requests.post(webhook.url, data=models.Event(
            type="test",
        ).json())

    return f.Response(status_code=204)


# Run the API
if __name__ == "__main__":
    database.init_db()
    threading.Thread(name="Event Manager (planned)", target=planned_event_manager, daemon=True).start()
    threading.Thread(name="Event Manager (open)", target=open_event_manager, daemon=True).start()
    uvicorn.run(app, port=globals.lazy_config.e["api.port"])
