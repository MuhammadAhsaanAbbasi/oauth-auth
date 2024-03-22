from oauth_auth import setting
from sqlmodel import SQLModel, create_engine, Session

connectionstring = str(setting.DATABASE_URL).replace(
    "postgresql", "postgresql+psycopg"
)

engine = create_engine(connectionstring, connect_args={"sslmode" : "require"}, pool_recycle=600)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session