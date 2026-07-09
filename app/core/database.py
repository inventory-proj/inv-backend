import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Получаем данные из защищенных переменных окружения (в будущем - из K8s Secrets)
DB_USER = os.getenv("POSTGRES_USER", "administrator")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "password")
DB_NAME = os.getenv("POSTGRES_DB", "inventory")
DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = os.getenv("DB_PORT", "5432")

# Формируем DSN (Data Source Name)
SQLALCHEMY_DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Создаем движок (Engine). 
# Важно: SQLAlchemy АВТОМАТИЧЕСКИ использует параметризованные запросы под капотом!
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
