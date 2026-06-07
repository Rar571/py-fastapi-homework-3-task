import secrets
from datetime import datetime, timezone, timedelta

from fastapi.responses import JSONResponse
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import TokenExpiredError, InvalidTokenError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserActivation,
    UserPasswordRequestReset,
    UserPasswordCompleteReset,
    UserLogin,
    UserAccessTokenRefresh,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter()


@router.post("/register/")
async def register_user(
    user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    existed_user = await db.execute(
        select(UserModel).where(UserModel.email == user.email)
    )
    existed_user = existed_user.scalar_one_or_none()
    if existed_user is not None:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists.",
        )
    try:
        hashed_password = hash_password(user.password)
        group_result = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        group = group_result.scalar_one_or_none()
        if group is None:
            raise HTTPException(
                status_code=500, detail="An error occurred during user creation."
            )
        token = secrets.token_urlsafe(32)
        user_create = UserModel(
            email=user.email, _hashed_password=hashed_password, group_id=group.id
        )
        db.add(user_create)
        await db.flush()
        activation_token = ActivationTokenModel(
            token=token,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            user_id=user_create.id,
        )
        db.add(activation_token)
        await db.commit()
        await db.refresh(user_create)
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )
    return JSONResponse(
        status_code=201, content={"id": user_create.id, "email": user.email}
    )


@router.post("/activate/")
async def activate_user_account(
    user_data: UserActivation, db: AsyncSession = Depends(get_db)
):
    user_result = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    user = user_result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token_result = await db.execute(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    )
    token = token_result.scalar_one_or_none()

    if token is None:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    if token.token != user_data.token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    token.expires_at = token.expires_at.replace(tzinfo=timezone.utc)

    if token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/")
async def reset_user_password(
    user_data: UserPasswordRequestReset, db: AsyncSession = Depends(get_db)
):
    user_result = await db.execute(
        select(UserModel).where(
            UserModel.email == user_data.email, UserModel.is_active is True
        )
    )
    user = user_result.scalar_one_or_none()
    if user is None:
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }
    await db.flush()
    old_token_result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )
    old_token = old_token_result.scalar_one_or_none()
    if old_token:
        await db.delete(old_token)
    token = secrets.token_urlsafe(32)
    token_model = PasswordResetTokenModel(
        token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        user_id=user.id,
    )
    db.add(token_model)
    await db.commit()
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=200)
async def reset_user_password_complete(
    user_data: UserPasswordCompleteReset, db: AsyncSession = Depends(get_db)
):
    user_result = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    user = user_result.scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if user.is_active is False:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )
    token = token_result.scalar_one_or_none()

    if token is None:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if user_data.token != token.token:
        await db.delete(token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token.expires_at = token.expires_at.replace(tzinfo=timezone.utc)

    if token.expires_at < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        hashed_password = hash_password(user_data.password)
        user._hashed_password = hashed_password
        await db.delete(token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )
    return {"message": "Password reset successfully."}


@router.post("/login/", status_code=201)
async def user_login(
    user_data: UserLogin,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user_result = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    user = user_result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    hashed_password = user._hashed_password

    if not verify_password(user_data.password, hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if user.is_active is False:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    await db.flush()

    try:
        access_token = jwt_manager.create_access_token(
            {"sub": user.email, "user_id": user.id}
        )

        refresh_token = jwt_manager.create_refresh_token(
            {"sub": user.email, "user_id": user.id}
        )

        db_refresh_token = RefreshTokenModel.create(
            user_id=user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token
        )

        db.add(db_refresh_token)
        await db.commit()
    except Exception:
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh/")
async def refresh_user_access_token(
    refresh_token: UserAccessTokenRefresh,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        jwt_manager.decode_refresh_token(refresh_token.refresh_token)
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(status_code=400, detail="Token has expired.")

    refresh_token_result = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_token.refresh_token
        )
    )
    existed_refresh_token = refresh_token_result.scalar_one_or_none()

    if existed_refresh_token is None:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_result = await db.execute(
        select(UserModel).where(UserModel.id == existed_refresh_token.user_id)
    )
    user = user_result.scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token(
        {"sub": user.email, "user_id": user.id}
    )

    await db.commit()
    return {"access_token": access_token}
