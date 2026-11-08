"""
Authentication Endpoints for AEGIS Backend.
- POST /api/auth/login   : username + password -> signed session token (rate-limited)
- GET  /api/auth/me      : current identity (username, tenant, role)
- POST /api/auth/logout  : revokes the current session token
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from aegis_backend.config import settings
from aegis_backend.tenancy import (
    AuthUser,
    DEV_USER,
    SUPERADMIN_TENANT,
    clear_login_failures,
    extract_client_ip,
    get_auth_store,
    get_request_user,
    issue_token,
    login_lock_remaining,
    register_login_failure,
    revoke_token,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class UserInfo(BaseModel):
    username: str
    tenant: str
    tenant_name: str
    role: str
    is_superadmin: bool
    auth_enabled: bool = True


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserInfo


def _user_info(user: AuthUser) -> UserInfo:
    return UserInfo(
        username=user.username,
        tenant=user.tenant,
        tenant_name=get_auth_store().tenant_name(user.tenant),
        role=user.role,
        is_superadmin=user.is_super,
        auth_enabled=settings.auth_enabled,
    )


@router.post("/login", response_model=LoginResponse, summary="Log in and obtain a session token")
def login(payload: LoginRequest, request: Request):
    ip = extract_client_ip(request)

    remaining = login_lock_remaining(ip, payload.username)
    if remaining > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {remaining} seconds.",
            headers={"Retry-After": str(remaining)},
        )

    if not settings.auth_enabled:
        store = get_auth_store()
        if store.has_users():
            user = store.authenticate(payload.username, payload.password)
            if user is None:
                register_login_failure(ip, payload.username)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username or password.",
                )
            clear_login_failures(ip, payload.username)
            token, ttl = issue_token(user)
            return LoginResponse(access_token=token, expires_in=ttl, user=_user_info(user))

        # When no user database exists, permit only explicit dev user
        if payload.username.lower() in ("admin", "dev"):
            token, ttl = issue_token(DEV_USER)
            return LoginResponse(access_token=token, expires_in=ttl, user=_user_info(DEV_USER))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    user: Optional[AuthUser] = get_auth_store().authenticate(payload.username, payload.password)
    if user is None:
        register_login_failure(ip, payload.username)
        # Identical message for unknown user and wrong password (no user enumeration).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    clear_login_failures(ip, payload.username)
    token, ttl = issue_token(user)
    return LoginResponse(access_token=token, expires_in=ttl, user=_user_info(user))


@router.get("/me", response_model=UserInfo, summary="Current authenticated identity")
def me(user: AuthUser = Depends(get_request_user)):
    return _user_info(user)


@router.post("/logout", summary="Revoke the current session token")
def logout(request: Request, user: AuthUser = Depends(get_request_user)):
    header = request.headers.get("authorization", "")
    parts = header.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        revoke_token(parts[1].strip())
    return {"status": "ok", "message": f"Session for '{user.username}' has been closed."}

