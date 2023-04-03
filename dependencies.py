from authorization import get_bearer_token
from custom_exceptions import PermissionDenied
from fastapi import Depends, HTTPException, status
from token_verify import JsonWebToken
from auth0.authentication import Users as Auth_Users
from auth0.management import Users
from config import settings


def validate_token(token: str = Depends(get_bearer_token)):
    return JsonWebToken(token).validate()

class RoleValidator:
    def __init__(self, required_role: str, auth0_token):
        self.auth0_users = Users(settings.domain, auth0_token)
        self.auth0_auth_users = Auth_Users(settings.domain)
        self.required_role = required_role

    def __call__(self, token: str = Depends(validate_token)):
        user_role = self.auth0_users.list_roles(token['sub'], 0, 25, False)
        validation = False
        for role in user_role:
            if role['id'] == self.required_role:
                validation = True
        if not validation:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="FORBIDDEN")
