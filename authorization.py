from typing import NamedTuple
from custom_exceptions import BadCredentials, RequiresAuthentication
from starlette.requests import Request as StarletteRequest

class AuthorizationHeaderElements(NamedTuple):
    auth_scheme: str
    bearer_token: str
    is_valid: bool

def get_authorization_headers(authorization_headers: str) -> AuthorizationHeaderElements:
    try:
        auth_scheme, bearer_token = authorization_headers.split()
    except ValueError:
        raise BadCredentials
    valid = auth_scheme.lower() == 'bearer' and bool(bearer_token.strip())
    return AuthorizationHeaderElements(auth_scheme, bearer_token, valid)


def get_bearer_token(request: StarletteRequest) -> str:
    authorization_header = request.headers.get("Authorization")
    if authorization_header:
        authorization_header_elements = get_authorization_headers(authorization_header)
        if authorization_header_elements.is_valid:
            return authorization_header_elements.bearer_token
        else:
            raise BadCredentials
    else:
        raise RequiresAuthentication