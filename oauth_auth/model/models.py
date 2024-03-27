from sqlmodel import SQLModel, Field
from typing import Optional
import datetime
from pydantic import BaseModel, EmailStr

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True)
    email: str = Field(index=True, unique=True)
    hashed_password: Optional[str] = Field(index=True, nullable=True)
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    role: str = Field(default="user")
    created_at: datetime.datetime = Field(default=datetime.datetime.now(datetime.timezone.utc))
    updated_at: datetime.datetime = Field(default=datetime.datetime.now(datetime.timezone.utc))

class New_User():
    username: str
    email: EmailStr
    is_active: bool | None = True
    is_verified: bool | None = False

class RegisterUser(New_User):
    password: str | None = None

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str

class TokenData(BaseModel):
    username: str | None = None
    email: str | None = None

class Todo(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(foreign_key="user.id")
    title: str = Field(index=True)
    status: bool = Field(default=False)
    created_at: datetime.datetime = Field(default=datetime.datetime.now(datetime.timezone.utc))
    updated_at: datetime.datetime = Field(default=datetime.datetime.now(datetime.timezone.utc))