from starlette.config import Config
from starlette.datastructures import Secret

try:
    config = Config(".env")
except FileNotFoundError:
    config = Config()

DATABASE_URL = config("DATABASE_URL", cast=Secret)
SECRET_KEY = config("SECRET_KEY", cast=str)
ALGORITHM = config("ALGORITHM", cast=str)

REDIRECT_URI = config("REDIRECT_URI", cast=str)
FRONTEND_CLIENT_SUCCESS_URI = config("FRONTEND_CLIENT_SUCCESS_URI", cast=str)
FRONTEND_CLIENT_FAILURE_URI = config("FRONTEND_CLIENT_FAILURE_URI", cast=str)   