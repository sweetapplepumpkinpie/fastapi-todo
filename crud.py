from typing import Generator
from fastapi import Depends, HTTPException, status
from pydantic import ValidationError
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from jose import jwt
from database import SessionLocal
import secrets
import models
import schemas
import logging

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALGORITHM = "HS256"
reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl="api/login"
)
secret_key = secrets.token_urlsafe(32)


def get_db() -> Generator:
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = password_context.hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def login(db: Session, user: schemas.User):
    expire = datetime.utcnow() + timedelta(minutes=60 * 24 * 8)
    to_encode = {"exp": expire, "sub": str(user.id)}
    encoded_jwt = jwt.encode(
        to_encode, secret_key, algorithm=ALGORITHM)
    return {"access_token": encoded_jwt, "token_type": "bearer"}


def register(db: Session, user: schemas.UserCreate):
    hashed_password = password_context.hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    user = get_user_by_email(db, db_user.email)
    expire = datetime.utcnow() + timedelta(minutes=60 * 24 * 8)
    to_encode = {"exp": expire, "sub": str(user.id)}
    encoded_jwt = jwt.encode(
        to_encode, secret_key, algorithm=ALGORITHM)
    return {"access_token": encoded_jwt, "token_type": "bearer"}


def get_todos(db: Session, skip: int = 0, limit: int = 100, user_id: int = 0):
    return db.query(models.Todo).filter(models.Todo.owner_id == user_id).offset(skip).limit(limit).all()


def get_current_user(db: Session = Depends(get_db), token: str = Depends(reusable_oauth2)) -> schemas.User:
    try:
        payload = jwt.decode(
            token, secret_key, algorithms=[ALGORITHM]
        )
        token_data = schemas.TokenPayload(**payload)
    except (jwt.JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials."
        )
    user = get_user(db, user_id=token_data.sub)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def create_todo(db: Session, todo: schemas.TodoCreate):
    db_todo = models.Todo(**todo)
    db.add(db_todo)
    db.commit()
    db.refresh(db_todo)
    return db_todo


def read_todo(db: Session, id: int):
    return db.query(models.Todo).filter(models.Todo.id == id).first()
