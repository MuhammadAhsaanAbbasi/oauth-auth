from fastapi import APIRouter, Depends,  Form, Request, HTTPException, status
from fastapi.responses import RedirectResponse, JSONResponse, Response
from ..service.auth import create_user, login_for_access_token, token_manager, google_user
from ..model.models import User, Token
from typing import Annotated, Optional
from sqlmodel import Session, select
from ..data.db import get_session
from ..utils.auth import get_current_active_user
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

@router.get("/signout")
def signout():
    return {"message": "login"}

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
        user_email = idinfo['email']

        user_name = idinfo['name']

        # Check if the user exists in your database. If the user doesn't exist, add the user to the database
        new_google_user = await google_user(session, email=user_email, username=user_name)
        if new_google_user is None:
            raise HTTPException(status_code=400, detail="User not found")
        
        return new_google_user

        # After running nextjs project UCOMMENT THE FOLLOWING CODE and COMMENT OUT THE ABOVE RETURN line

        # response = RedirectResponse(url='http://localhost:3000/user')
        # response.set_cookie(key="email", value=idinfo['email'], httponly=True)
        # response.set_cookie(key="name", value=idinfo['name'], httponly=True)
        # response.set_cookie(key="picture", value=idinfo['picture']  , httponly=True)
        # # Note: Don't set sensitive data in non-httponly cookies if it's not necessary
        # response.set_cookie(key="google_user_data", value=json.dumps(idinfo)  , httponly=True)
        # return response
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

@router.post("/sign-up")
def sign_up(user: User, session: Annotated[Session, Depends(get_session)]):
    user = create_user(user, session)
    return user

@router.post("/login", response_model=Token)
async def login_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: Annotated[Session, Depends(get_session)]):
    token = await login_for_access_token(form_data, session)
    return token

@router.post("/token")
async def get_tokens(session: Annotated[Session, Depends(get_session)], grant_type:str = Form(...), refresh_token:Optional[str] = Form(None)):
    tokens = await token_manager(session, grant_type, refresh_token)
    return tokens

@router.get("/user/me", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user