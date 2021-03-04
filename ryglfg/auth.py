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
class Auth0CustomClaims(p.BaseModel):
    iss: str
    sub: str
    aud: str
    iat: int
    exp: int
    azp: str
    scope: str
    permissions: t.List[str]


class Auth0CustomUser(faca.Auth0CurrentUser):
    user_info = Auth0CustomClaims


# Objects exported by this module
__all__ = (
    "Auth0CustomClaims",
    "Auth0CustomUser",
)
