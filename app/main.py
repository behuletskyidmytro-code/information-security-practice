
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


@app.post("/auth/login", tags=["Authentication"])
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
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


@app.get("/auth/me", response_model=UserInfo, tags=["Authentication"])
def read_me(user: User = Depends(get_current_user)):
    return {
        "username": user.username,
        "roles": [role.name for role in user.roles],
    }


@app.get("/students", tags=["Students"])
def students(user: User = Depends(get_current_user)):
    return {"message": "Students endpoint"}


@app.get("/teachers", tags=["Teachers"])
def teachers(user: User = Depends(get_current_user)):
    return {"message": "Teachers endpoint"}


@app.get("/admin/users", tags=["Admin"])
def admin_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    users = db.query(User).all()
    return {
        "users": [user.username for user in users]
    }
