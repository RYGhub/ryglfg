# Module docstring
"""

"""

# Special imports
from __future__ import annotations
import royalnet.royaltyping as t

# External imports
import logging
import pydantic as p
import datetime

# Internal imports
from .database import AnnouncementState, ResponseChoice, WebhookFormat

# Special global objects
log = logging.getLogger(__name__)


# Code
class Model(p.BaseModel):
    pass


class ORMModel(Model):
    class Config(p.BaseConfig):
        orm_mode = True


class AnnouncementEditable(ORMModel):
    title: str
    description: str
    opening_time: datetime.datetime
    autostart_time: datetime.datetime


class ResponseEditable(ORMModel):
    choice: ResponseChoice


class WebhookEditable(ORMModel):
    url: str
    format: WebhookFormat


class AnnouncementBasic(AnnouncementEditable):
    aid: int
    creator_id: str
    creation_time: datetime.datetime
    editing_time: datetime.datetime
    closer_id: t.Optional[str]
    closure_time: t.Optional[datetime.datetime]
    state: AnnouncementState


class ResponseBasic(ResponseEditable):
    aid: int
    partecipant_id: str
    posting_time: datetime.datetime
    editing_time: datetime.datetime


class WebhookBasic(WebhookEditable):
    wid: int


class AnnouncementFull(AnnouncementBasic):
    responses: t.List[ResponseBasic]


class ResponseFull(ResponseBasic):
    announcement: AnnouncementBasic


class WebhookFull(WebhookBasic):
    pass


class Event(Model):
    type: str


class EventAnnouncement(Event):
    announcement: AnnouncementFull


class EventResponse(Event):
    response: ResponseFull
    code: int


# Objects exported by this module
__all__ = (
    "AnnouncementEditable",
    "ResponseEditable",
    "WebhookEditable",
    "AnnouncementBasic",
    "ResponseBasic",
    "WebhookBasic",
    "AnnouncementFull",
    "ResponseFull",
    "WebhookFull",
    "Event",
    "EventAnnouncement",
    "EventResponse",
)
