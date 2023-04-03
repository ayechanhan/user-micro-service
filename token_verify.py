from dataclasses import dataclass
from custom_exceptions import BadCredentials, UnableCredentails
import jwt
from config import settings
from fastapi import HTTPException, status
import http.client
import json


def get_auth0_token():
    conn = http.client.HTTPSConnection(settings.domain)
    payload = json.dumps({"client_id": settings.client_id, "client_secret": settings.client_secret, "audience": "https://dev-1rrbp5l1k0qfs843.us.auth0.com/api/v2/", "grant_type": "client_credentials"})
    headers = {'content-type': "application/json"}
    conn.request("POST", "/oauth/token", payload, headers)
    res = conn.getresponse()
    data = res.read()
    decoded_data = data.decode("utf-8")
    return json.loads(decoded_data)["access_token"]

@dataclass
class JsonWebToken:
    access_token: str
    issuer_url: str = f"http://{settings.domain}"
    audience: str = settings.audience
    algorithm: str = "RS256"
    uri: str = f"{issuer_url}/.well-known/jwks.json"

    def validate(self):
        try:
            client = jwt.PyJWKClient(self.uri)
            signing_key = client.get_signing_key_from_jwt(
                self.access_token
            ).key
            payload = jwt.decode(
                self.access_token,
                signing_key,
                algorithms=self.algorithm,
                audience=self.audience,
            )
        except jwt.exceptions.InvalidTokenError:
            raise BadCredentials
        except jwt.exceptions.PyJWKClientError:
            raise UnableCredentails
        return payload
