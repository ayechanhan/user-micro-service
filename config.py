from pydantic import BaseSettings, validator

class Settings(BaseSettings):
    audience: str
    client_id: str
    client_secret: str
    domain: str
    db_host: str
    db_user: str
    db_password: str
    front_end_url: str
    port: int
    reload: bool
    user_role: str
    admin_role: str

    @classmethod
    @validator("front_end_url", "audience", "domain", "db_host", "db_user", "db_password")
    def check_env(cls, v):
        assert v != "", f"{v} is not defined"
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()