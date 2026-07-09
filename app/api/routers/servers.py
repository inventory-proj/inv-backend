import urllib.request
import urllib.parse
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.core.database import get_db
from app.core.security import get_current_user, check_server_permissions
from app.models.domain import Workspace, Server, WorkspaceMember
from app.schemas.domain import ServerCreate, ServerRename, ServerMove

router = APIRouter()

@router.post("/servers")
def create_server(data: ServerCreate, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    ws = db.query(Workspace).filter(Workspace.id == data.workspace_id).first()
    if not ws or str(ws.owner_id) != str(current_user['user_id']):
        raise HTTPException(status_code=403, detail="Только владелец группы может добавлять серверы")
        
    new_server = Server(
        hostname=data.hostname, 
        ip_address=data.ip_address, 
        workspace_id=data.workspace_id, 
        creator_id=current_user['user_id']
    )
    try:
        db.add(new_server)
        db.commit()
        db.refresh(new_server)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Сервер с таким именем уже есть в этой группе")
        
    return {"status": "ok", "agent_token": str(new_server.agent_token)}

@router.put("/servers/{server_id}/rename")
def rename_server(server_id: int, data: ServerRename, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Сервер не найден")
        
    check_server_permissions(server, current_user['user_id'], 'rename')
    
    try:
        server.hostname = data.hostname
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Имя уже занято в этой группе")
        
    return {"status": "ok"}

@router.put("/servers/{server_id}/move")
def move_server(server_id: int, data: ServerMove, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Сервер не найден")
        
    check_server_permissions(server, current_user['user_id'], 'move')
    
    # Проверка, что юзер состоит в целевой группе
    target_member = db.query(WorkspaceMember).filter(
        WorkspaceMember.workspace_id == data.target_workspace_id, 
        WorkspaceMember.user_id == current_user['user_id']
    ).first()
    
    if not target_member:
        raise HTTPException(status_code=403, detail="Вы не состоите в целевой группе")
        
    # Делегирование прав (только если переносит изначальный создатель)
    is_creator = (str(server.creator_id) == str(current_user['user_id']))
    
    server.workspace_id = data.target_workspace_id
    server.delegated_can_delete = data.delegated_can_delete if is_creator else False
    server.delegated_can_rename = data.delegated_can_rename if is_creator else False
    server.delegated_can_view_agent = data.delegated_can_view_agent if is_creator else False
    
    db.commit()
    return {"status": "ok"}

@router.delete("/servers/{server_id}")
def archive_server(server_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Сервер не найден")
        
    check_server_permissions(server, current_user['user_id'], 'delete')
    server.status = 'archived'
    db.commit()
    return {"status": "ok"}

@router.get("/servers/{server_id}/logs")
def get_server_logs(server_id: int, job: str = "varlogs", limit: int = 150, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Сервер не найден")
        
    # Базовая проверка прав на просмотр (состоит ли юзер в группе сервера)
    member = db.query(WorkspaceMember).filter(
        WorkspaceMember.workspace_id == server.workspace_id,
        WorkspaceMember.user_id == current_user['user_id']
    ).first()
    
    if not member:
        raise HTTPException(status_code=403, detail="У вас нет доступа к логам этого сервера")

    if not server.agent_token:
        raise HTTPException(status_code=404, detail="Агент не инициализирован")

    token = str(server.agent_token)
    query = f'{{job="{job}"}}'
    encoded_query = urllib.parse.quote(query)
    loki_url = f"http://loki-service:3100/loki/api/v1/query?query={encoded_query}&limit={limit}"
    
    req = urllib.request.Request(loki_url)
    req.add_header("X-Scope-OrgID", token)
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            logs = []
            if data.get("status") == "success":
                for stream in data.get("data", {}).get("result", []):
                    for val in stream.get("values", []):
                        logs.append({"ts": val[0], "line": val[1]})
            logs.sort(key=lambda x: x["ts"])
            return {"status": "ok", "logs": logs}
    except Exception:
        return {"status": "error", "logs": [], "detail": "Логи временно недоступны"}
