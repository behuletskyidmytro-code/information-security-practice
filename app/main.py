
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

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

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


# Security headers
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return response


# Rate limiting: 5 login requests per minute per IP
login_attempts = defaultdict(deque)


def check_login_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    attempts = login_attempts[client_ip]

    while attempts and now - attempts[0] >= 60:
        attempts.popleft()

    if len(attempts) >= 5:
        retry_after = max(1, int(60 - (now - attempts[0])) + 1)
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    attempts.append(now)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Database
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# JWT authentication
def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    try:
        payload = decode_access_token(token)
        username = payload.get("sub")
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not username:
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.username == username).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


# Role-based access control
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


# System
@app.get("/health", tags=["System"])
def health_check():
    return {"status": "ok"}


# Authentication
@app.post("/auth/login", tags=["Authentication"])
def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    check_login_rate_limit(request)

    user = db.query(User).filter(
        User.username == form.username
    ).first()

    if not user or not verify_password(
        form.password, user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user.username)

    return {
        "access_token": token,
        "token_type": "bearer",
    }


@app.get(
    "/auth/me",
    response_model=UserInfo,
    tags=["Authentication"],
)
def read_me(user: User = Depends(get_current_user)):
    return {
        "username": user.username,
        "roles": [role.name for role in user.roles],
    }


# Students
@app.get("/students", tags=["Students"])
def students(user: User = Depends(get_current_user)):
    return {"message": "Students endpoint"}


# Teachers
@app.get("/teachers", tags=["Teachers"])
def teachers(user: User = Depends(get_current_user)):
    return {"message": "Teachers endpoint"}


# Admin
@app.get("/admin/users", tags=["Admin"])
def admin_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    users = db.query(User).all()

    return {
        "users": [user.username for user in users]
    }
