import os
import json
import re
from fastapi import FastAPI, Query, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, EmailStr, Field
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

DB_USER = os.getenv("POSTGRES_USER", "administrator")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "password")
DB_NAME = os.getenv("POSTGRES_DB", "inventory")
DB_HOST = os.getenv("DB_HOST", "db")
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_secret_for_local_dev")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@contextmanager
def get_db_cursor(commit=False):
    conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST)
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

# --- СХЕМЫ ---
class LoginData(BaseModel):
    email: EmailStr
    password: str

class UserCreate(BaseModel):
    username: str = Field(..., pattern=r'^[a-zA-Z0-9_]{3,30}$')
    email: EmailStr
    password: str

class WorkspaceCreate(BaseModel):
    name: str

class ServerCreate(BaseModel):
    hostname: strвот еще кстати проблема, я создал еще одного пользователя 52 и добавил ему в группу себя, почему я не вижу его группу и себя в ней, а у 52 есть я, но сервера у нас не отображаются, все таки давай наверно вернем кнопку создания групп и управления ими, чтобы на главном экране появлялись названия групп свернутые, а потом нажав на стрелку развернуть - показывались все сервера в этой группе,  чтобы можно было создавать в основной панели группы, а добавлять участников через уже созданную группу в главном окне управления, рядом с кнопкой развернуть группу, добавить участника и добавить сервер в группу, примерно так
    ip_address: str
    workspace_id: int
    cluster_id: int | None = None

class InviteData(BaseModel):
    username: str
    workspace_id: int

# --- АВТОРИЗАЦИЯ ---
def get_current_user(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    token = auth_header.split(" ")[1]
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        raise HTTPException(status_code=401, detail="Неверный или просроченный токен")

def require_global_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != "global_admin":
        raise HTTPException(status_code=403, detail="Доступ только для администраторов")
    return user

def verify_server_access(cur, server_id: int, user_id: int):
    cur.execute("""
        SELECT s.workspace_id FROM servers s
        JOIN workspace_members wm ON s.workspace_id = wm.workspace_id
        WHERE s.id = %s AND wm.user_id = %s
    """, (server_id, user_id))
    if not cur.fetchone():
        raise HTTPException(status_code=403, detail="У вас нет доступа к этому серверу")

# --- ЭНДПОИНТЫ АВТОРИЗАЦИИ ---
@app.post("/api/login")
def login(data: LoginData):
    with get_db_cursor() as cur:
        cur.execute("""
            SELECT u.id, u.username, u.email, u.password_hash, r.role_name 
            FROM users u JOIN roles r ON u.role_id = r.id 
            WHERE u.email = %s
        """, (data.email,))
        user = cur.fetchone()

    if user and pwd_context.verify(data.password, user['password_hash']):
        token = jwt.encode(
            {"user_id": user['id'], "username": user['username'], "email": user['email'], "role": user['role_name']}, 
            SECRET_KEY, algorithm="HS256"
        )
        return {"token": token, "role": user['role_name'], "email": user['email'], "username": user['username']}
    raise HTTPException(status_code=401, detail="Неверная почта или пароль")

@app.post("/api/users")
def register_user(user_data: UserCreate):
    hashed_pwd = pwd_context.hash(user_data.password)
    try:
        with get_db_cursor(commit=True) as cur:
            cur.execute("SELECT id FROM roles WHERE role_name = 'tenant_admin'")
            role = cur.fetchone()
            
            cur.execute(
                "INSERT INTO users (username, email, password_hash, role_id) VALUES (%s, %s, %s, %s) RETURNING id",
                (user_data.username, user_data.email, hashed_pwd, role['id'])
            )
            new_user_id = cur.fetchone()['id']
            
            # Создаем первую группу по имени юзера
            ws_name = f"Группа - {user_data.username}"
            cur.execute(
                "INSERT INTO workspaces (name, owner_id) VALUES (%s, %s) RETURNING id",
                (ws_name, new_user_id)
            )
            new_workspace_id = cur.fetchone()['id']
            
            cur.execute(
                "INSERT INTO workspace_members (workspace_id, user_id) VALUES (%s, %s)",
                (new_workspace_id, new_user_id)
            )
        return {"status": "ok"}
    except psycopg2.IntegrityError as e:
        error_msg = str(e)
        if 'users_username_key' in error_msg:
            raise HTTPException(status_code=400, detail="Этот никнейм уже занят")
        raise HTTPException(status_code=400, detail="Эта почта уже зарегистрирована")

# --- CORE: ЭНДПОИНТ ДАШБОРДА ---
@app.get("/api/dashboard")
def get_dashboard(current_user: dict = Depends(get_current_user)):
    """Возвращает все группы юзера, их серверы и участников за один запрос"""
    with get_db_cursor() as cur:
        # 1. Получаем все группы, где юзер состоит
        cur.execute("""
            SELECT w.id, w.name, w.owner_id 
            FROM workspaces w
            JOIN workspace_members wm ON w.id = wm.workspace_id
            WHERE wm.user_id = %s
            ORDER BY w.id ASC
        """, (current_user['user_id'],))
        workspaces = cur.fetchall()

        # 2. Наполняем группы данными
        for ws in workspaces:
            ws['is_owner'] = (ws['owner_id'] == current_user['user_id'])
            
            # Серверы группы
            cur.execute("""
                SELECT id, hostname, ip_address, status, agent_token 
                FROM servers 
                WHERE workspace_id = %s AND status != 'archived'
                ORDER BY id ASC
            """, (ws['id'],))
            ws['servers'] = cur.fetchall()
            
            # Участники группы
            cur.execute("""
                SELECT u.username, u.email 
                FROM workspace_members wm
                JOIN users u ON wm.user_id = u.id
                WHERE wm.workspace_id = %s
            """, (ws['id'],))
            ws['members'] = cur.fetchall()

        return workspaces

# --- WORKSPACES И ИНВАЙТЫ ---
@app.post("/api/workspaces")
def create_workspace(data: WorkspaceCreate, current_user: dict = Depends(get_current_user)):
    with get_db_cursor(commit=True) as cur:
        cur.execute("INSERT INTO workspaces (name, owner_id) VALUES (%s, %s) RETURNING id", (data.name, current_user['user_id']))
        ws_id = cur.fetchone()['id']
        cur.execute("INSERT INTO workspace_members (workspace_id, user_id) VALUES (%s, %s)", (ws_id, current_user['user_id']))
    return {"status": "ok"}

@app.post("/api/team/invite")
def invite_to_team(data: InviteData, current_user: dict = Depends(get_current_user)):
    clean_username = data.username.strip('@')
    
    with get_db_cursor(commit=True) as cur:
        # Проверяем, что юзер - владелец именно ЭТОЙ группы
        cur.execute("SELECT owner_id FROM workspaces WHERE id = %s", (data.workspace_id,))
        ws = cur.fetchone()
        if not ws or ws['owner_id'] != current_user['user_id']:
            raise HTTPException(status_code=403, detail="Только создатель группы может приглашать участников")

        cur.execute("SELECT id, username FROM users WHERE username = %s", (clean_username,))
        target_user = cur.fetchone()
        if not target_user:
            raise HTTPException(status_code=404, detail="Пользователь с таким никнеймом не найден")
        
        if target_user['id'] == current_user['user_id']:
            raise HTTPException(status_code=400, detail="Нельзя пригласить самого себя")

        try:
            cur.execute("INSERT INTO workspace_members (workspace_id, user_id) VALUES (%s, %s)", (data.workspace_id, target_user['id']))
        except psycopg2.IntegrityError:
            raise HTTPException(status_code=400, detail="Этот пользователь уже в группе")
            
    return {
        "status": "ok", 
        "message": f"Пользователь @{target_user['username']} добавлен!",
        "invite_link": f"https://inv.e-laba52.ru/?team_invite={data.workspace_id}"
    }

# --- ЭНДПОИНТЫ СЕРВЕРОВ ---
@app.post("/api/servers")
def create_server(server: ServerCreate, current_user: dict = Depends(get_current_user)):
    with get_db_cursor(commit=True) as cur:
        # Проверяем, состоит ли юзер в этой группе (добавлять могут все участники)
        cur.execute("SELECT 1 FROM workspace_members WHERE workspace_id = %s AND user_id = %s", (server.workspace_id, current_user['user_id']))
        if not cur.fetchone():
            raise HTTPException(status_code=403, detail="У вас нет доступа к этой группе")
        
        try:
            cur.execute("""
                INSERT INTO servers (hostname, ip_address, cluster_id, workspace_id) 
                VALUES (%s, %s, %s, %s) 
                RETURNING id, agent_token
            """, (server.hostname, server.ip_address, server.cluster_id, server.workspace_id))
            new_server = cur.fetchone()
        except psycopg2.IntegrityError:
            raise HTTPException(status_code=400, detail="Сервер с таким именем уже есть в этой группе")
            
    return {
        "status": "ok", 
        "agent_token": new_server['agent_token'],
        "install_command": f"curl -sL https://inv.e-laba52.ru/agent.sh | sudo bash -s -- --token={new_server['agent_token']}"
    }

@app.delete("/api/servers/{server_id}")
def archive_server(server_id: int, current_user: dict = Depends(get_current_user)):
    with get_db_cursor(commit=True) as cur:
        verify_server_access(cur, server_id, current_user['user_id'])
        cur.execute("UPDATE servers SET status = 'archived' WHERE id = %s;", (server_id,))
    return {"status": "ok"}

@app.get("/api/export")
def export_database(current_user: dict = Depends(require_global_admin)):
    with get_db_cursor() as cur:
        cur.execute("SELECT id, hostname, ip_address, status FROM servers")
        servers = cur.fetchall()
    json_str = json.dumps({"servers": servers}, indent=4, ensure_ascii=False)
    return Response(content=json_str, media_type="application/json", headers={"Content-Disposition": "attachment; filename=backup.json"})
