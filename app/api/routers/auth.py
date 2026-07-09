from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import verify_password, get_password_hash, create_access_token
from app.models.domain import User, Role, Workspace, WorkspaceMember
from app.schemas.domain import LoginData, UserCreate

router = APIRouter()

@router.post("/login")
def login(data: LoginData, db: Session = Depends(get_db)):
    # ORM SQLAlchemy автоматически параметризует этот запрос. SQL-инъекция невозможна.
    user = db.query(User).filter(User.email == data.email).first()
    
    if not user or not verify_password(data.password, user.password_hash):
        # БЕЗОПАСНОСТЬ: Никогда не пишем "Неверный пароль" или "Пользователь не найден".
        # Всегда даем общий ответ, чтобы хакер не мог перебирать базу логинов (User Enumeration).
        raise HTTPException(status_code=401, detail="Неверная почта или пароль")
    
    # В будущем (на этапе внедрения Email-микросервиса) здесь будет проверка:
    # if not user.is_verified:
    #     raise HTTPException(status_code=403, detail="Подтвердите Email")

    token = create_access_token({
        "user_id": user.id, 
        "username": user.username, 
        "email": user.email, 
        "role": user.role.role_name if user.role else "viewer"
    })
    
    return {
        "token": token, 
        "role": user.role.role_name if user.role else "viewer", 
        "email": user.email, 
        "username": user.username
    }

@router.post("/users")
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    # Проверка уникальности
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Эта почта уже зарегистрирована")
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Этот никнейм уже занят")
        
    role = db.query(Role).filter(Role.role_name == "tenant_admin").first()
    
    # Создание пользователя
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=get_password_hash(user_data.password),
        role_id=role.id if role else None,
        is_verified=True # ВРЕМЕННО: Изменим на False, когда добавим Redis и отправку писем
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Автоматическое создание дефолтной рабочей группы для нового пользователя
    new_ws = Workspace(name=f"Группа - {new_user.username}", owner_id=new_user.id)
    db.add(new_ws)
    db.commit()
    db.refresh(new_ws)
    
    # Добавление пользователя в его же группу
    db.add(WorkspaceMember(workspace_id=new_ws.id, user_id=new_user.id))
    db.commit()
    
    return {"status": "ok"}
