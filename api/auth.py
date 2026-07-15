"""JWT authentication utilities for the NetSentinel API.

Provides token creation, verification, and login flow.  Auth is only
active when ``config.auth.enabled`` is ``True``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
import bcrypt

from config.settings import get_config
from utils.logger import setup_logger

logger = setup_logger("netsentinel.api.auth")

_bearer_scheme = HTTPBearer(auto_error=False)


def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT access token.

    Args:
        data: Payload claims to encode (must contain ``sub``).
        expires_delta: Custom expiry duration.  Falls back to config value.

    Returns:
        Encoded JWT string.
    """
    config = get_config()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta
        or timedelta(minutes=config.auth.token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(
        to_encode,
        config.auth.secret_key,
        algorithm=config.auth.algorithm,
    )


def verify_token(token: str) -> dict[str, Any] | None:
    """Decode and verify a JWT token.

    Args:
        token: Raw JWT string.

    Returns:
        Decoded payload dict on success, ``None`` on any failure.
    """
    config = get_config()
    try:
        payload = jwt.decode(
            token,
            config.auth.secret_key,
            algorithms=[config.auth.algorithm],
        )
        return payload
    except JWTError as exc:
        logger.debug("Token verification failed: %s", exc)
        return None


def authenticate_user(username: str, password: str) -> bool:
    """Validate credentials against the configured admin user.

    Args:
        username: Username to check.
        password: Plaintext password to verify against stored hash.

    Returns:
        ``True`` if credentials match, ``False`` otherwise.
    """
    config = get_config()
    if username != config.auth.username:
        return False
    stored_hash = config.auth.password_hash.encode("utf-8")
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(
        _bearer_scheme
    ),
) -> dict[str, Any]:
    """FastAPI dependency that extracts and validates the current user.

    Returns:
        User dict with at least a ``username`` key.

    Raises:
        HTTPException 401 if auth is enabled and the token is missing or
        invalid.
    """
    config = get_config()
    if not config.auth.enabled:
        return {"username": "anonymous", "role": "admin"}

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username: str | None = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject claim",
        )

    return {"username": username, "role": payload.get("role", "admin")}


def login(username: str, password: str) -> str | None:
    """Authenticate and return a JWT token string.

    Args:
        username: Username.
        password: Plaintext password.

    Returns:
        JWT string on success, ``None`` if credentials are invalid.
    """
    if not authenticate_user(username, password):
        logger.warning("Failed login attempt for user '%s'", username)
        return None

    token = create_access_token(data={"sub": username, "role": "admin"})
    logger.info("User '%s' authenticated successfully", username)
    return token
