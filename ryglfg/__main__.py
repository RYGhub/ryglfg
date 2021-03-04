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
import fastapi as f
import fastapi.middleware.cors as cors
import sqlalchemy.sql as ss

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
)
CurrentUser = auth.Auth0CustomUser(domain=config["authzero.domain"])


# API routes
@app.get(
    "/auth",
    summary="Check your user status.",
    response_model=auth.Auth0CustomClaims,
    tags=["Authorization"],
)
def auth_get(*,
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
    tags=["Announcements"],
)
def lfg_get(*,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),

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

    with database.lazy_Session.e(future=True) as session:
        query = ss.select(database.Announcement)
        query = query.where(database.Announcement.state == filter_state) if filter_state else query
        query = query.offset(offset)
        query = query.limit(limit)
        query = query.order_by(database.Announcement.autostart_time)
        results = session.execute(query)
        return [models.AnnouncementFull.from_orm(result) for result in results.scalars()]


@app.post(
    "/lfg",
    summary="Post a new LFG.",
    response_model=models.AnnouncementFull,
    tags=["Announcements"]
)
def lfg_post(*,
             cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
             data: models.AnnouncementEditable = f.Body(..., description="The data of the LFG you are creating.")
             ):
    """
    Create a new LFG with the passed data.

    Requires the `create:lfg` scope.
    """
    if "create:lfg" not in cu.permissions:
        raise f.HTTPException(403, "Missing `read:lfg` scope.")

    with database.lazy_Session.e(future=True) as session:
        lfg = database.Announcement(**data.dict(), creator_id=cu.sub)
        session.add(lfg)
        session.commit()
        return models.AnnouncementFull.from_orm(lfg)


@app.get(
    "/lfg/{aid}",
    summary="Get info about a single LFG.",
    response_model=models.AnnouncementFull,
    tags=["Announcements"]
)
def lfg_get_single(*,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        aid: int = f.Path(..., description="The aid of the LFG to retrieve."),
):
    """
    Return the requested LFG.

    Requires the `read:lfg` scope.
    """
    if "read:lfg" not in cu.permissions:
        raise f.HTTPException(403, "Missing `read:lfg` scope.")

    with database.lazy_Session.e(future=True) as session:
        query = ss.select(database.Announcement)
        query = query.where(database.Announcement.aid == aid)
        results = session.execute(query)
        lfg = results.scalar()
        if lfg is None:
            raise f.HTTPException(404, "No such LFG.")
        return models.AnnouncementFull.from_orm(lfg)


@app.put(
    "/lfg/{aid}",
    summary="Edit a LFG.",
    response_model=models.AnnouncementFull,
    tags=["Announcements"]
)
def lfg_put(*,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        aid: int = f.Path(..., description="The aid of the LFG to edit."),
        data: models.AnnouncementEditable = f.Body(..., description="The new data of the LFG.")
):
    """
    Set the data of the specified LFG to the request body.

    Requires the `edit:lfg` scope, and additionally requires the `administrate:lfg` scope if you aren't the creator
    of the LFG or if the LFG has started or has been cancelled.
    """
    if "edit:lfg" not in cu.permissions:
        raise f.HTTPException(403, "Missing `edit:lfg` scope.")

    with database.lazy_Session.e(future=True) as session:
        query = ss.select(database.Announcement)
        query = query.where(database.Announcement.aid == aid)
        results = session.execute(query)
        lfg: t.Optional[database.Announcement] = results.scalar()
        if lfg is None:
            raise f.HTTPException(404, "No such LFG.")
        if (lfg.creator_id != cu.sub
            or lfg.state == database.AnnouncementState.EVENT_STARTED
            or lfg.state == database.AnnouncementState.EVENT_CANCELLED
        ) and "administrate:lfg" not in cu.permissions:
            raise f.HTTPException(403, "Missing `administrate:lfg` scope.")
        lfg.update(**data.dict())
        session.commit()
        return models.AnnouncementFull.from_orm(lfg)


@app.delete(
    "/lfg/{aid}",
    summary="Quietly delete a LFG.",
    status_code=204,
    tags=["Announcements"]
)
def lfg_delete(*,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser),
        aid: int = f.Path(..., description="The aid of the LFG to edit."),
):
    """
    Quietly delete a LFG without triggering any webhook or notification.

    Requires the `administrate:lfg` scope.
    """
    if "administrate:lfg" not in cu.permissions:
        raise f.HTTPException(403, "Missing `administrate:lfg` scope.")

    with database.lazy_Session.e(future=True) as session:
        query = ss.select(database.Announcement)
        query = query.where(database.Announcement.aid == aid)
        results = session.execute(query)
        lfg: t.Optional[database.Announcement] = results.scalar()
        if lfg is None:
            raise f.HTTPException(404, "No such LFG.")
        session.delete(lfg)
        session.commit()
        return f.Response(status_code=204)


@app.delete(
    "/lfg/{aid}/start",
    summary="Start a LFG.",
    response_model=models.AnnouncementFull,
    tags=["Announcements"],
    deprecated=True,
)
def lfg_start(*,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser)
):
    ...


@app.delete(
    "/lfg/{aid}/cancel",
    summary="Cancel a LFG.",
    response_model=models.AnnouncementFull,
    tags=["Announcements"],
    deprecated=True,
)
def lfg_cancel(*,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser)
):
    ...


@app.put(
    "/lfg/{aid}/respond",
    summary="Answer an open LFG.",
    response_model=models.ResponseFull,
    tags=["Responses"],
    deprecated=True,
)
def lfg_respond(*,
        cu: auth.Auth0CustomClaims = f.Depends(CurrentUser)
):
    ...


# Run the API
if __name__ == "__main__":
    database.init_db()
    uvicorn.run(app, port=globals.lazy_config.e["api.port"])
