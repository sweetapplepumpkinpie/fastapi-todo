import email
from typing import List

from fastapi import Depends, FastAPI, HTTPException, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from passlib.context import CryptContext

import crud
import models
import schemas
from database import SessionLocal, engine
import logging


models.Base.metadata.create_all(bind=engine)
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI()
origins = [
    "http://localhost",
    "http://localhost:3000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


router = APIRouter(prefix="/api")


@router.get("/me", response_model=schemas.User)
def get_me(
    current_user: models.User = Depends(crud.get_current_user),
):
    return current_user


@router.post("/register/", response_model=schemas.Token)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(
            status_code=400, detail="Email already registered")
    return crud.register(db=db, user=user)


@router.post("/login/", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=form_data.username)
    if db_user:
        if password_context.verify(form_data.password, db_user.hashed_password):
            return crud.login(db=db, user=db_user)
    raise HTTPException(
        status_code=400, detail="Email or password is invalid.")


@router.post("/users/", response_model=schemas.User)
def create_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(crud.get_current_user),
):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user)


@router.get("/users/", response_model=List[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@router.get("/todos/", response_model=List[schemas.Todo])
def read_todos(skip: int = 0, limit: int = 100, db: Session = Depends(get_db),
               current_user: models.User = Depends(crud.get_current_user),
               ):
    todos = crud.get_todos(db, skip=skip, limit=limit,
                           user_id=current_user.id)
    return todos


@router.post("/todos/", response_model=List[schemas.Todo])
def create_todo(
    todo: schemas.TodoCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(crud.get_current_user),
):
    return crud.create_todo(db=db, todo=todo)


@router.get("/todos/{id}", response_model=List[schemas.Todo])
def read_todo(
    *,
    db: Session = Depends(get_db),
    id: int,
    current_user: models.User = Depends(crud.get_current_user),
):
    return crud.read_todo(db=db, id=id)


app.include_router(router)
