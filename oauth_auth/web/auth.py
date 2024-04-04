from fastapi import APIRouter, Depends,  Form, Request, HTTPException, status
from fastapi.responses import RedirectResponse, JSONResponse, Response
from ..service.auth import create_user, login_for_access_token, google_user, create_active_user_todo
from ..model.models import User, Token, Todo
from typing import Annotated, Optional
from sqlmodel import Session, select
from ..data.db import get_session
from ..utils.auth import get_current_active_user, tokens_service, oauth2_scheme
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
import os
import json

# Google Import
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport import requests as google_requests

# Authentication Import 
from ..setting import FRONTEND_CLIENT_SUCCESS_URI, FRONTEND_CLIENT_FAILURE_URI, REDIRECT_URI

# To avoid error: Exception occurred: (insecure_transport) OAuth 2 MUST utilize https.
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for testing, remove for production

# Load the secrets file
current_file_path = os.path.abspath(__file__)
# print(f"current file: {current_file_path}")

# Get the parent directory of the current file's directory
parent_directory = os.path.dirname(current_file_path)
# print(f"parent file: {parent_directory}")

# Get the parent directory of the parent directory
Child_DIR = os.path.dirname(parent_directory)


# Get the Chlid directory of the parent directory
BASE_DIR = os.path.dirname(Child_DIR)


# Define the path to the client_secret.json file
CLIENT_SECRET_FILE = os.path.join(BASE_DIR, 'client_secret.json')
# print(f"client file: {CLIENT_SECRET_FILE}")
SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']

# Router
router = APIRouter(prefix="/api/auth")

# Google Login
@router.get("/google/login")
async def login(request:Request):
    flow = Flow.from_client_secrets_file(CLIENT_SECRET_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    
    authorization_url, state = flow.authorization_url(
        # Access type 'offline' so that the token can be refreshed
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true'
    )
    request.session['state'] = state
    return RedirectResponse(authorization_url)

# Google Callback
@router.get("/google/callback")
async def auth(request: Request, session: Annotated[Session, Depends(get_session)]):
    try:
        state = request.session['state']

        if not state or state != request.query_params.get('state'):
            raise HTTPException(status_code=400, detail="State mismatch")

        flow = Flow.from_client_secrets_file(
            CLIENT_SECRET_FILE, scopes=SCOPES, state=state, redirect_uri=REDIRECT_URI)

        authorization_response = str(request.url)
        flow.fetch_token(authorization_response=authorization_response)

        credentials = flow.credentials
        # idinfo contains the Google user’s info.
        idinfo = id_token.verify_oauth2_token(
            credentials.id_token, google_requests.Request(), flow.client_config['client_id'])
        # print(idinfo)
        print(idinfo['name'])
        print(idinfo['email'])
        print(idinfo['picture'])
        
        user_email = idinfo['email']

        user_name = idinfo['name']
        
        user_picture = idinfo['picture']

        # Check if the user exists in your database. If the user doesn't exist, add the user to the database
        new_google_user = await google_user(session, email=user_email, username=user_name, picture=user_picture)
        if new_google_user is None:
            raise HTTPException(status_code=400, detail="User not found")
        
        return new_google_user
    except HTTPException as http_exception:
        # Log the exception for debugging
        print(f"HTTPException occurred: {http_exception.detail}")

        # Append a failure reason to the redirect URL
        failure_url = f"{FRONTEND_CLIENT_FAILURE_URI}?google_login_failed={http_exception.detail}"
        return RedirectResponse(url=failure_url)

    except Exception as exception:
        # Log the general exception for debugging
        print(f"Exception occurred: {exception}")

        # Append a generic failure message to the redirect URL
        failure_url = f"{FRONTEND_CLIENT_FAILURE_URI}?google_login_failed=error"
        return RedirectResponse(url=failure_url)

# Sign-up Routes
@router.post("/signup")
def sign_up(user: User, session: Annotated[Session, Depends(get_session)]):
    user = create_user(user, session)
    return user

# Login Routes
@router.post("/login", response_model=Token)
async def login_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: Annotated[Session, Depends(get_session)]):
    token = await login_for_access_token(form_data, session)
    return token

# token route
@router.post("/token", response_model=Token)
async def get_tokens(session: Annotated[Session, Depends(get_session)], refresh_token:Annotated[str, Depends(oauth2_scheme)]): 
    tokens = await tokens_service(refresh_token=refresh_token, session=session)
    return tokens

# user routes
@router.get("/user/me", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user

# user create todo
@router.post("/todo", response_model=Todo)
async def create_todo(todo:Todo, 
                    current_user: Annotated[User, Depends(get_current_active_user)],
                    session: Annotated[Session, Depends(get_session)]):
    todo = create_active_user_todo(todo, current_user, session=session)
    return todo

# user get todos
@router.get("/todo", response_model=list[Todo])
async def get_todos(current_user: Annotated[User, Depends(get_current_active_user)],
                    session: Annotated[Session, Depends(get_session)]):
    todos = session.exec(select(Todo).where(Todo.user_id == current_user.id)).all()
    return todos

@router.delete("/todo/{todo_id}")
def delete_todo(todo_id: int, current_user: Annotated[User, Depends(get_current_active_user)],
                    session: Annotated[Session, Depends(get_session)]):
    todo = session.exec(select(Todo).where(Todo.id == todo_id, Todo.user_id == current_user.id)).first()
    if todo:
        session.delete(todo)
        session.commit()
        return todo
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Todo not found")