import time
from collections import defaultdict, deque
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database import SessionLocal
from app.models import User
from app.security import (
    verify_password,
    create_access_token,
    decode_access_token,
)

app = FastAPI(
    title="Електронний деканат",
    description="Захищений REST API для навчального закладу",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'"
    return response


login_attempts = defaultdict(deque)


def check_login_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    attempts = login_attempts[client_ip]

    while attempts and now - attempts[0] >= 60:
        attempts.popleft()

    if len(attempts) >= 5:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts",
        )

    attempts.append(now)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    try:
        payload = decode_access_token(token)
        username = payload.get("sub")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


def require_role(role_name: str):
    def check_role(user: User = Depends(get_current_user)):
        if not any(role.name == role_name for role in user.roles):
            raise HTTPException(
                status_code=403,
                detail="Access forbidden",
            )
        return user

    return check_role


class UserInfo(BaseModel):
    username: str
    roles: list[str]


@app.get("/health", tags=["System"])
def health_check():
    return {"status": "ok"}

from collections import defaultdict
from time import monotonic
from fastapi import Request

login_attempts = defaultdict(list)
@app.post("/auth/login", tags=["Authentication"])
def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    ip = request.client.host if request.client else "unknown"
    now = monotonic()

    # Залишаємо тільки спроби за останні 60 секунд
    attempts = [
        t for t in login_attempts[ip]
        if now - t < 60
    ]
    login_attempts[ip] = attempts

    # Максимум 5 спроб за 60 секунд
    if len(attempts) >= 5:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": "60"},
        )

    login_attempts[ip].append(now)

    user = db.query(User).filter(
        User.username == form.username
    ).first()

    if not user or not verify_password(
        form.password, user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    token = create_access_token(user.username)

    return {
        "access_token": token,
        "token_type": "bearer",
    }
