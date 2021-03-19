# Module docstring
"""

"""

# Special imports
from __future__ import annotations
import royalnet.royaltyping as t

# External imports
import logging
import pydantic as p
import fastapi_cloudauth.auth0 as faca

# Internal imports
# from . import something

# Special global objects
log = logging.getLogger(__name__)


# Code
class Auth0AccessClaims(p.BaseModel):
    iss: str
    sub: str
    aud: t.Union[t.List[str], str]
    iat: int
    exp: int
    azp: str
    scope: str
    permissions: t.List[str]
    ryg_name: str = p.Field(..., alias="https://meta.ryg.one/name")
    ryg_picture: p.HttpUrl = p.Field(..., alias="https://meta.ryg.one/picture")


class Auth0User(faca.Auth0CurrentUser):
    user_info = Auth0AccessClaims


# Objects exported by this module
__all__ = (
    "Auth0AccessClaims",
    "Auth0User",
)
