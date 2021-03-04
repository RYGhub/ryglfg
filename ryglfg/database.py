# Module docstring
"""

"""

# Special imports
from __future__ import annotations
import royalnet.royaltyping as t

# External imports
import logging
import sqlalchemy as s
import sqlalchemy.orm as so
import sqlalchemy.exc as sexc
import royalnet.lazy as lazy
import datetime
import enum
import royalnet.alchemist as ra

# Internal imports
from .globals import lazy_config

# Special global objects
log = logging.getLogger(__name__)
now = datetime.datetime.now


# Code
Base = so.declarative_base()
lazy_engine = lazy.Lazy(lambda c: s.create_engine(c["database.uri"]), c=lazy_config)
lazy_Session = lazy.Lazy(lambda e: s.orm.sessionmaker(bind=e), e=lazy_engine)


def init_db() -> None:
    """
    Initialize the database, creating the database itself and the tables that are missing.
    """
    engine = lazy_engine.evaluate()
    # noinspection PyPep8Naming
    # Session = lazy_Session.evaluate()

    log.debug("Creating the tables based on the declarative base metadata...")
    Base.metadata.create_all(bind=engine)

    # log.debug("Initializing the table contents...")
    # with Session(future=True) as session:
    #     pass

    log.debug("Database initialization complete!")


def determine_default_autoclose_time(context):
    return context.get_current_parameters()["creation_time"] + datetime.timedelta(hours=1)


class AnnouncementState(enum.IntEnum):
    PLANNED = -1
    OPEN = 0
    STARTED = 1
    CANCELLED = 2


class Announcement(Base, ra.ColRepr, ra.Updatable):
    __tablename__ = "lfg_announcements"

    aid = s.Column("aid", s.Integer, primary_key=True)

    title = s.Column("title", s.String, nullable=False, default="")
    description = s.Column("description", s.Text, nullable=False, default="")
    creator_id = s.Column("creator_id", s.String, nullable=False)
    creation_time = s.Column("creation_time", s.DateTime, nullable=False,  default=now)
    editing_time = s.Column("editing_time", s.DateTime, nullable=False, default=now, onupdate=now)
    opening_time = s.Column("opening_time", s.DateTime, nullable=False, default=now)
    autostart_time = s.Column("autostart_time", s.DateTime, nullable=False, default=determine_default_autoclose_time)
    closer_id = s.Column("closer_id", s.String)
    closure_time = s.Column("closure_time", s.DateTime)
    state = s.Column("state", s.Enum(AnnouncementState), nullable=False, default=AnnouncementState.PLANNED)
    
    responses = so.relationship("Response", back_populates="announcement", cascade="all, delete-orphan")


class ResponseChoice(str, enum.Enum):
    ACCEPTED = "accepted"
    LATE = "late"
    REJECTED = "rejected"
    NOT_AVAILABLE = "not_available"
    UNSET = "unset"


class Response(Base, ra.ColRepr, ra.Updatable):
    __tablename__ = "lfg_responses"

    aid = s.Column("aid", s.Integer, s.ForeignKey(Announcement.aid), primary_key=True)
    partecipant_id = s.Column("partecipant_id", s.String, primary_key=True)

    posting_time = s.Column("posting_time", s.DateTime, nullable=False, default=now)
    editing_time = s.Column("editing_time", s.DateTime, nullable=False, default=now, onupdate=now)
    choice = s.Column("choice", s.Enum(ResponseChoice), nullable=False, default=ResponseChoice.UNSET)

    announcement = so.relationship("Announcement", back_populates="responses")


class WebhookFormat(str, enum.Enum):
    RYGLFG = "ryglfg"


class Webhook(Base, ra.ColRepr, ra.Updatable):
    __tablename__ = "lfg_webhooks"

    wid = s.Column("aid", s.Integer, primary_key=True)

    url = s.Column("url", s.String, nullable=False)
    format = s.Column("format", s.Enum(WebhookFormat), nullable=False, default=WebhookFormat.RYGLFG)


# noinspection PyPep8Naming
def DatabaseSession():
    Session = lazy_Session.evaluate()
    with Session(future=True) as session:
        yield session


# Objects exported by this module
__all__ = (
    "lazy_engine",
    "lazy_Session",
    "init_db",
    "AnnouncementState",
    "Announcement",
    "ResponseChoice",
    "Response",
    "WebhookFormat",
    "Webhook",
    "DatabaseSession",
)
