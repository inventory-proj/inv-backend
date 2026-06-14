import os
import json
from fastapi import FastAPI, Query, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
import psycopg2
import jwt
from passlib.context import CryptContext

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_USER = os.getenv("POSTGRES_USER", "admin")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "password")
DB_NAME = os.getenv("POSTGRES_DB", "inventory")
DB_HOST = os.getenv("DB_HOST", "db")
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_secret_for_local_dev")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db_connection():
    return psycopg2.connect(
        dbname=DB_NAME, 
        user=DB_USER, 
        password=DB_PASSWORD, 
        host=DB_HOST
    )

class LoginData(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    password: str
    role_id: int

class ServerCreate(BaseModel):
    hostname: str
    ip_address: str
    cluster_id: int

def get_current_user(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Неверный токен")

def require_admin(user: dict = Depends(get_current_user)):
    if user.get("role") not in ["admin", "devops"]:
        raise HTTPException(status_code=403, detail="Недостаточно прав.")
    return user

@app.post("/api/login")
def login(data: LoginData):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.username, u.password_hash, r.role_name 
        FROM users u JOIN roles r ON u.role_id = r.id 
        WHERE u.username = %s
    """, (data.username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user and pwd_context.verify(data.password, user[2]):
        token = jwt.encode({"user_id": user[0], "username": user[1], "role": user[3]}, SECRET_KEY, algorithm="HS256")
        return {"token": token, "role": user[3], "username": user[1]}
    raise HTTPException(status_code=401, detail="Неверный логин или пароль")

@app.get("/api/servers")
def get_servers(sort: str = Query("asc"), user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cur = conn.cursor()
    sort_order = "DESC" if sort.lower() == "desc" else "ASC"
    query = f"""
        SELECT s.id, s.hostname, s.ip_address, c.cluster_name, s.status 
        FROM servers s JOIN clusters c ON s.cluster_id = c.id 
        ORDER BY s.id {sort_order}
    """
    cur.execute(query)
    servers = [{"id": row[0], "hostname": row[1], "ip": row[2], "cluster": row[3], "status": row[4]} for row in cur.fetchall()]
    cur.close()
    conn.close()
    return servers

@app.post("/api/users")
def create_user(user: UserCreate, current_admin: dict = Depends(require_admin)):
    hashed_pwd = pwd_context.hash(user.password)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash, role_id) VALUES (%s, %s, %s)", (user.username, hashed_pwd, user.role_id))
        conn.commit()
    except Exception:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Ошибка (имя занято)")
    finally:
        cur.close()
        conn.close()
    return {"status": "ok"}

@app.post("/api/servers")
def create_server(server: ServerCreate, current_admin: dict = Depends(require_admin)):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO servers (hostname, ip_address, cluster_id) VALUES (%s, %s, %s)", (server.hostname, server.ip_address, server.cluster_id))
    conn.commit()
    cur.close()
    conn.close()
    return {"status": "ok"}

@app.delete("/api/servers/{server_id}")
def archive_server(server_id: int, current_admin: dict = Depends(require_admin)):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE servers SET status = 'archived' WHERE id = %s;", (server_id,))
    conn.commit()
    cur.close()
    conn.close()
    return {"status": "ok"}

@app.put("/api/servers/{server_id}/restore")
def restore_server(server_id: int, current_admin: dict = Depends(require_admin)):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE servers SET status = 'active' WHERE id = %s;", (server_id,))
    conn.commit()
    cur.close()
    conn.close()
    return {"status": "ok"}

@app.put("/api/servers/{server_id}/maintenance")
def maintenance_server(server_id: int, current_admin: dict = Depends(require_admin)):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("CALL enable_maintenance(%s);", (server_id,))
    conn.commit()
    cur.close()
    conn.close()
    return {"status": "ok"}

@app.get("/api/export")
def export_database(current_admin: dict = Depends(require_admin)):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, hostname, ip_address, status FROM servers")
    servers = [{"id": row[0], "hostname": row[1], "ip_address": row[2], "status": row[3]} for row in cur.fetchall()]
    cur.close()
    conn.close()
    
    json_str = json.dumps({"servers": servers}, indent=4, ensure_ascii=False)
    return Response(content=json_str, media_type="application/json", headers={"Content-Disposition": "attachment; filename=backup.json"})
