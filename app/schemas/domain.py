from pydantic import BaseModel, EmailStr, Field

# ==========================================
# ВАЛИДАЦИЯ ВВОДА (Input Sanitization)
# Строгий White-list символов по заветам OWASP.
# ==========================================

class LoginData(BaseModel):
    email: EmailStr
    password: str

class UserCreate(BaseModel):
    # Никнейм: только латиница, цифры и подчеркивание, от 3 до 30 символов.
    username: str = Field(..., pattern=r'^[a-zA-Z0-9_]{3,30}$')
    email: EmailStr
    # Пароль: минимум 6 символов
    password: str = Field(..., min_length=6)

class WorkspaceCreate(BaseModel):
    # Название группы: Буквы, цифры, пробел, тире, подчеркивание. 
    # Никаких HTML-тегов или кавычек.
    name: str = Field(..., pattern=r'^[a-zA-Zа-яА-Я0-9\s_-]{3,50}$')

class ServerCreate(BaseModel):
    # Имя сервера: только латиница, цифры, точка, тире. (Защита от RCE: запрет `|`, `;`, `&`)
    hostname: str = Field(..., pattern=r'^[a-zA-Z0-9.-]{2,100}$')
    # IP адрес: строгая проверка формата IPv4
    ip_address: str = Field(..., pattern=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    workspace_id: int

class ServerMove(BaseModel):
    target_workspace_id: int
    delegated_can_delete: bool = False
    delegated_can_rename: bool = False
    delegated_can_view_agent: bool = False

class ServerRename(BaseModel):
    # Те же строгие правила, что и при создании
    hostname: str = Field(..., pattern=r'^[a-zA-Z0-9.-]{2,100}$')

class InviteData(BaseModel):
    username: str = Field(..., pattern=r'^[a-zA-Z0-9_]{3,30}$')
    workspace_id: int
