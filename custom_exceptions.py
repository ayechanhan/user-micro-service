from fastapi import status, HTTPException

class BadCredentials(HTTPException):
    def __init__(self):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bad Credentials")

class PermissionDenied(HTTPException):
    def __init__(self):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail="Permission Denied")

class RequiresAuthentication(HTTPException):
    def __init__(self):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail="Require Authentication")

class UnableCredentails(HTTPException):
    def __init__(self):
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to verify credentials")