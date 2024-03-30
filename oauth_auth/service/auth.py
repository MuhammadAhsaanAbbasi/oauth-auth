from typing import Annotated, Optional
from sqlmodel import  Session, select
from fastapi import Depends, HTTPException, Form
from ..data.db import get_session
from ..model.models import User, Token, Todo
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
from ..utils.auth import authenticate_user, get_password_hash, create_access_token, create_refresh_token, tokens_service, get_current_active_user
from datetime import timedelta
from ..utils.auth import REFRESH_TOKEN_EXPIRE_MINUTES, ACCESS_TOKEN_EXPIRE_MINUTES
import string
import secrets

def create_user(user: User, session: Annotated[Session, Depends(get_session)]):
    email = session.exec(select(User).where(User.email == user.email)).first()
    if email:
        raise HTTPException(status_code=400, detail="Email already registered")
    user.hashed_password = get_password_hash(user.hashed_password)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: Annotated[Session, Depends(get_session)])->Token:
    user = authenticate_user(User, form_data.username, form_data.password, session)
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

        # Generate refresh token (you might want to set a longer expiry for this)
    refresh_token_expires = timedelta(minutes=float(REFRESH_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_refresh_token(data={"email": user.email}, expires_delta=refresh_token_expires)
    print(ACCESS_TOKEN_EXPIRE_MINUTES)
    return Token(access_token=access_token, token_type="bearer", expires_in= int(access_token_expires.total_seconds()), refresh_token=refresh_token)

async def token_manager(session: Annotated[Session, Depends(get_session)], grant_type:str = Form(...), refresh_token:Optional[str] = Form(None)):
    if grant_type == 'refresh_token':
        if not refresh_token:
            raise HTTPException(status_code=400, detail='refresh token is required')
        return await tokens_service(str(refresh_token), session)
    elif grant_type == "authorization_code":
        pass
    else:
        raise HTTPException(status_code=400, detail='grant type is required')

async def google_user(session: Annotated[Session, Depends(get_session)], username:str, email:str, picture:str):
    user = session.exec(select(User).where(User.email == email)).first()
    try:
        if user is None:
            password_length = 12  # You can choose the length of the password
            characters = string.ascii_letters + string.digits + string.punctuation
            random_password = ''.join(secrets.choice(characters) for i in range(password_length))
            user_data = User(username=username, email=email, hashed_password=random_password, imageUrl=picture)
            
            new_user = await create_user(user_data, session)
            return new_user
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
                    data={"sub": user.username}, expires_delta=access_token_expires)
        refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
        refresh_token = create_refresh_token(
                    data={"sub": user.email}, expires_delta=refresh_token_expires)
        response = RedirectResponse(url='http://localhost:3000/user/me')
        response.set_cookie(key="access_token", value=access_token, httponly=True)
        response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, expires=REFRESH_TOKEN_EXPIRE_MINUTES)
        # response.set_cookie(key="picture", value=idinfo['picture']  , httponly=True)
        # # Note: Don't set sensitive data in non-httponly cookies if it's not necessary
        # response.set_cookie(key="google_user_data", value=json.dumps(idinfo)  , httponly=True)
        return response
    except HTTPException as e:
        # Re-raise the exception to be handled in the web layer
        raise e
    except Exception as e:
        # Re-raise general exceptions to be handled in the web layer
        raise e

def create_active_user_todo(todo:Todo, current_user: Annotated[User, Depends(get_current_active_user)], session: Annotated[Session, Depends(get_session)]):
    print(f"user_id {current_user.id}")
    if current_user:
        todo.user_id = current_user.id
    else:
        raise HTTPException(status_code=400, detail="User not found")
    session.add(todo)
    session.commit()
    session.refresh(todo)
    return todo

