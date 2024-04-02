FROM python:3.12

WORKDIR /app

RUN apt update && apt install pipx -y && pipx ensurepath 

RUN pipx install poetry

COPY . .

ENV PATH="${PATH}:/root/.local/bin"

RUN poetry install

CMD [ "poetry" , 'run ' , 'uvicorn'  , 'oauth_auth.main:app', '--reload', '--host', '0.0.0.0', '--port', '8000']