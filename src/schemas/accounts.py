import re

from fastapi import HTTPException
from pydantic import BaseModel, EmailStr, field_validator


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @staticmethod
    def check_password_strength(password: str):
        if len(password) < 8:
            raise HTTPException(
                status_code=422, detail="Password must contain at least 8 characters."
            )
        if not re.search(r"[A-Z]", password):
            raise HTTPException(
                status_code=422,
                detail="Password must contain at least one uppercase letter.",
            )
        if not re.search(r"[a-z]", password):
            raise HTTPException(
                status_code=422,
                detail="Password must contain at least one lower letter.",
            )
        if not re.search(r"\d", password):
            raise HTTPException(
                status_code=422, detail="Password must contain at least one digit."
            )
        if not re.search(r"[@$!%*?&#]", password):
            raise HTTPException(
                status_code=422,
                detail="Password must contain at least one special character: @, $, !, %, *, ?, #, &.",
            )
        return password


class UserActivation(UserBase):
    token: str


class UserPasswordRequestReset(UserBase):
    pass


class UserPasswordCompleteReset(UserRegistrationRequestSchema):
    token: str


class UserLogin(UserRegistrationRequestSchema):
    pass


class UserAccessTokenRefresh(BaseModel):
    refresh_token: str
