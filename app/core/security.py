import os
import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext

# БЕЗОПАСНОСТЬ: Ключ будет браться из переменных окружения K8s Secrets
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change-me-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Токен живет 15 минут по стандарту OWASP

# Настройка bcrypt для хэширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security_scheme = HTTPBearer()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Время действия токена истекло. Авторизуйтесь заново.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Неверный или поврежденный токен")

def require_global_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != "global_admin":
        raise HTTPException(status_code=403, detail="Доступ только для администраторов")
    return user

# УНИВЕРСАЛЬНАЯ ЗАЩИТА СЕРВЕРОВ (RBAC) с жесткой типизацией строк
def check_server_permissions(server, user_id: int, required_action: str):
    if not server:
        raise HTTPException(status_code=404, detail="Сервер не найден")
        
    # Защита от бага типизации (строгое приведение к строке)
    is_creator = str(server.creator_id) == str(user_id)
    is_owner = str(server.workspace.owner_id) == str(user_id)
    
    # 1. Создатель может всё
    if is_creator:
        return True
        
    # 2. Не владелец группы - отказ
    if not is_owner:
        raise HTTPException(status_code=403, detail="Только владелец группы может управлять сервером")
        
    # 3. Владелец может перенести чужой сервер из своей группы
    if required_action == 'move':
        return True
        
    # 4. Проверка делегированных прав (галочек)
    if required_action == 'delete' and not server.delegated_can_delete:
        raise HTTPException(status_code=403, detail="Создатель запретил удалять этот сервер")
    elif required_action == 'rename' and not server.delegated_can_rename:
        raise HTTPException(status_code=403, detail="Создатель запретил переименовывать этот сервер")
    elif required_action == 'view_agent' and not server.delegated_can_view_agent:
        raise HTTPException(status_code=403, detail="Создатель скрыл токен агента")
        
    return True
