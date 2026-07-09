import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# БЕЗОПАСНОСТЬ И K8S: Используем префикс POSTGRES_, чтобы избежать коллизий 
# с автоматически генерируемыми переменными сервисов Kubernetes (типа DB_PORT=tcp://...)
DB_USER = os.getenv("POSTGRES_USER", "administrator")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "password")
DB_NAME = os.getenv("POSTGRES_DB", "inventory")
DB_HOST = os.getenv("POSTGRES_HOST", "db")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")

# Формируем DSN (Data Source Name)
SQLALCHEMY_DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Создаем движок (Engine). SQLAlchemy АВТОМАТИЧЕСКИ использует параметризованные запросы!
engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency для получения сессии БД в эндпоинтах
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
