from fastapi import APIRouter, HTTPException, Depends, Request, Response, Form
from sqlmodel import select
from app.database import SessionDep
from app.models import *
from app.auth import encrypt_password, verify_password, create_access_token, AuthDep
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from fastapi import status
from fastapi.responses import HTMLResponse, RedirectResponse
from app.utilities import flash

todo_router = APIRouter(tags=["Todo Management"])

@todo_router.post("/todos")
def create_todo_action(request: Request, text: Annotated[str, Form()], db:SessionDep, user:AuthDep):
    # Implement task 4.2 here. Remove the line below that says "pass" once complete
    pass