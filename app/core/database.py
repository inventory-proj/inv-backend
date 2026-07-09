import os
from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker, declarative_base

# БЕЗОПАСНОСТЬ: Используем префикс POSTGRES_, чтобы избежать коллизий 
# с автоматически генерируемыми переменными сервисов Kubernetes (типа DB_PORT=tcp://...)
DB_USER = os.getenv("POSTGRES_USER", "administrator")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "password")
DB_NAME = os.getenv("POSTGRES_DB", "inventory")
DB_HOST = os.getenv("POSTGRES_HOST", "db")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")

# БЕЗОПАСНОСТЬ: НИКОГДА не собираем DSN через f-строки!
# Используем URL.create, чтобы SQLAlchemy автоматически и безопасно 
# экранировал (url-encode) любые спецсимволы (@, /, %) в пароле.
SQLALCHEMY_DATABASE_URL = URL.create(
    drivername="postgresql",
    username=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=DB_PORT,
    database=DB_NAME
)

# Создаем движок (Engine). SQLAlchemy АВТОМАТИЧЕСКИ использует параметризованные запросы!
engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency для получения изолированной сессии БД в каждом эндпоинте API
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
