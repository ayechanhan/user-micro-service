from pydantic import BaseModel

class User(BaseModel):
    email: str
    password: str

class RegisterSchema(BaseModel):
    email:str
    password: str
    user_metadata: dict | None

class ChangePasswordSchema(BaseModel):
    email: str

class UserProfile(BaseModel):
    firstname: str | None
    lastname: str | None
    gender: str | None
    phone: str | None
    birthdate: str | None
    avatar: str | None
    address: str | None
    city: str | None
    postalcode: int | None
    state: str | None
    primary: bool | None
    label: str | None

class CreateUserSchema(BaseModel):
    email: str
    password: str
    role: str

class UpdateUserSchema(BaseModel):
    id: str
    firstname: str | None
    lastname: str | None
    gender: str | None
    phone: str | None
    birthdate: str | None
    avatar: str | None
    address: str | None
    city: str | None
    postalcode: int | None
    state: str | None
    primary: bool | None
    label: str | None
    role: str | None