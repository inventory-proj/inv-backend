import os
import json
from fastapi import FastAPI, Query, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
import jwt
from passlib.context import CryptContext
from contextlib import contextmanager

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Переменные окружения
DB_USER = os.getenv("POSTGRES_USER", "administrator")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "password")
DB_NAME = os.getenv("POSTGRES_DB", "inventory")
DB_HOST = os.getenv("DB_HOST", "db")
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_secret_for_local_dev")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ==========================================
# 1. БЕЗОПАСНАЯ РАБОТА С БД (Context Manager)
# ==========================================
@contextmanager
def get_db_cursor(commit=False):
    """
    Безопасное управление соединениями. 
    Гарантирует закрытие соединения при любых ошибках.
    """
    conn = psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST
    )
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        yield cur
        if commit:
            conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()


# ==========================================
# 2. СХЕМЫ ДАННЫХ (PYDANTIC)
# ==========================================
class LoginData(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    password: str
    workspace_name: str # Название компании/группы при регистрации

class ServerCreate(BaseModel):
    hostname: str
    ip_address: str
    workspace_id: int
    cluster_id: int | None = None


# ==========================================
# 3. АВТОРИЗАЦИЯ И ПРОВЕРКА ПРАВ
# ==========================================
def get_current_user(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Неверный или просроченный токен")

def require_global_admin(user: dict = Depends(get_current_user)):
    """Только для супер-админа платформы"""
    if user.get("role") != "global_admin":
        raise HTTPException(status_code=403, detail="Доступ только для администраторов платформы")
    return user

def verify_workspace_access(cur, workspace_id: int, user_id: int):
    """Вспомогательная функция: проверяет, состоит ли юзер в группе"""
    cur.execute("""
        SELECT 1 FROM workspace_members 
        WHERE workspace_id = %s AND user_id = %s
    """, (workspace_id, user_id))
    if not cur.fetchone():
        raise HTTPException(status_code=403, detail="У вас нет доступа к этому рабочему пространству")

def verify_server_access(cur, server_id: int, user_id: int):
    """Вспомогательная функция: проверяет права на конкретный сервер через его workspace"""
    cur.execute("""
        SELECT s.workspace_id FROM servers s
        JOIN workspace_members wm ON s.workspace_id = wm.workspace_id
        WHERE s.id = %s AND wm.user_id = %s
    """, (server_id, user_id))
    if not cur.fetchone():
        raise HTTPException(status_code=403, detail="У вас нет доступа к этому серверу")


# ==========================================
# 4. ЭНДПОИНТЫ (API)
# ==========================================

@app.post("/api/login")
def login(data: LoginData):
    with get_db_cursor() as cur:
        cur.execute("""
            SELECT u.id, u.username, u.password_hash, r.role_name 
            FROM users u JOIN roles r ON u.role_id = r.id 
            WHERE u.username = %s
        """, (data.username,))
        user = cur.fetchone()

    if user and pwd_context.verify(data.password, user['password_hash']):
        token = jwt.encode(
            {"user_id": user['id'], "username": user['username'], "role": user['role_name']}, 
            SECRET_KEY, 
            algorithm="HS256"
        )
        return {"token": token, "role": user['role_name'], "username": user['username']}
    
    raise HTTPException(status_code=401, detail="Неверный логин или пароль")

@app.post("/api/users")
def register_user(user_data: UserCreate):
    """
    Регистрация SaaS-клиента. Транзакция: Юзер + Workspace + Привязка.
    """
    hashed_pwd = pwd_context.hash(user_data.password)
    
    try:
        with get_db_cursor(commit=True) as cur:
            cur.execute("SELECT id FROM roles WHERE role_name = 'tenant_admin'")
            role = cur.fetchone()
            if not role:
                raise HTTPException(status_code=500, detail="Роль tenant_admin не найдена")
            
            # 1. Создаем пользователя
            cur.execute(
                "INSERT INTO users (username, password_hash, role_id) VALUES (%s, %s, %s) RETURNING id",
                (user_data.username, hashed_pwd, role['id'])
            )
            new_user_id = cur.fetchone()['id']
            
            # 2. Создаем Workspace
            cur.execute(
                "INSERT INTO workspaces (name, owner_id) VALUES (%s, %s) RETURNING id",
                (user_data.workspace_name, new_user_id)
            )
            new_workspace_id = cur.fetchone()['id']
            
            # 3. Привязываем
            cur.execute(
                "INSERT INTO workspace_members (workspace_id, user_id) VALUES (%s, %s)",
                (new_workspace_id, new_user_id)
            )
            
        return {"status": "ok", "workspace_id": new_workspace_id}
    except psycopg2.IntegrityError:
        raise HTTPException(status_code=400, detail="Пользователь с таким именем уже существует")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/workspaces")
def get_my_workspaces(current_user: dict = Depends(get_current_user)):
    """Получить список групп текущего пользователя"""
    with get_db_cursor() as cur:
        cur.execute("""
            SELECT w.id, w.name, w.owner_id 
            FROM workspaces w
            JOIN workspace_members wm ON w.id = wm.workspace_id
            WHERE wm.user_id = %s
        """, (current_user['user_id'],))
        workspaces = cur.fetchall()
    return workspaces

@app.post("/api/servers")
def create_server(server: ServerCreate, current_user: dict = Depends(get_current_user)):
    """Добавление сервера и генерация токена для агента"""
    with get_db_cursor(commit=True) as cur:
        verify_workspace_access(cur, server.workspace_id, current_user['user_id'])
        
        try:
            cur.execute("""
                INSERT INTO servers (hostname, ip_address, cluster_id, workspace_id) 
                VALUES (%s, %s, %s, %s) 
                RETURNING id, agent_token
            """, (server.hostname, server.ip_address, server.cluster_id, server.workspace_id))
            
            new_server = cur.fetchone()
        except psycopg2.IntegrityError:
            raise HTTPException(status_code=400, detail="Ошибка: возможно, сервер с таким именем уже есть")
            
    install_command = f"curl -sL https://inv.e-laba52.ru/agent.sh | sudo bash -s -- --token={new_server['agent_token']}"
    
    return {
        "status": "ok", 
        "server_id": new_server['id'],
        "agent_token": new_server['agent_token'],
        "install_command": install_command
    }

@app.get("/api/servers")
def get_servers(workspace_id: int = Query(...), current_user: dict = Depends(get_current_user)):
    """Получить список серверов КОНКРЕТНОЙ группы"""
    with get_db_cursor() as cur:
        verify_workspace_access(cur, workspace_id, current_user['user_id'])

        cur.execute("""
            SELECT s.id, s.hostname, s.ip_address, s.status, s.agent_token 
            FROM servers s 
            WHERE s.workspace_id = %s
            ORDER BY s.id ASC
        """, (workspace_id,))
        servers = cur.fetchall()
    return servers

@app.delete("/api/servers/{server_id}")
def archive_server(server_id: int, current_user: dict = Depends(get_current_user)):
    with get_db_cursor(commit=True) as cur:
        verify_server_access(cur, server_id, current_user['user_id'])
        cur.execute("UPDATE servers SET status = 'archived' WHERE id = %s;", (server_id,))
    return {"status": "ok"}

@app.put("/api/servers/{server_id}/restore")
def restore_server(server_id: int, current_user: dict = Depends(get_current_user)):
    with get_db_cursor(commit=True) as cur:
        verify_server_access(cur, server_id, current_user['user_id'])
        cur.execute("UPDATE servers SET status = 'active' WHERE id = %s;", (server_id,))
    return {"status": "ok"}

@app.put("/api/servers/{server_id}/maintenance")
def maintenance_server(server_id: int, current_user: dict = Depends(get_current_user)):
    with get_db_cursor(commit=True) as cur:
        verify_server_access(cur, server_id, current_user['user_id'])
        cur.execute("CALL enable_maintenance(%s);", (server_id,))
    return {"status": "ok"}

@app.get("/api/export")
def export_database(current_user: dict = Depends(require_global_admin)):
    """Экспорт разрешен ТОЛЬКО глобальному админу (владельцу SaaS)"""
    with get_db_cursor() as cur:
        cur.execute("SELECT id, hostname, ip_address, status FROM servers")
        servers = cur.fetchall()
    json_str = json.dumps({"servers": servers}, indent=4, ensure_ascii=False)
    return Response(
        content=json_str, 
        media_type="application/json", 
        headers={"Content-Disposition": "attachment; filename=backup.json"}
    )
