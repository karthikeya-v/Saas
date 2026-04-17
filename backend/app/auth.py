from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .db import get_db


def issue_token(user_id: int, settings: Settings) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.jwt_ttl_seconds)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str, settings: Settings) -> int:
    try:
        payload = jwt.decode(
            token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
        return int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def current_user_id(
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> int:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1].strip()
    return decode_token(token, settings)


def ensure_user(db: Session, apple_sub: str, tz: str = "UTC") -> int:
    row = db.execute(
        text("SELECT id FROM users WHERE apple_sub = :sub"), {"sub": apple_sub}
    ).first()
    if row:
        return int(row[0])
    result = db.execute(
        text("INSERT INTO users (apple_sub, tz) VALUES (:sub, :tz)"),
        {"sub": apple_sub, "tz": tz},
    )
    db.commit()
    return int(result.lastrowid)


def dev_login(
    apple_sub: str,
    tz: str,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> str:
    if not settings.dev_mode:
        raise HTTPException(status_code=403, detail="dev login disabled")
    user_id = ensure_user(db, apple_sub=apple_sub, tz=tz)
    return issue_token(user_id, settings)
