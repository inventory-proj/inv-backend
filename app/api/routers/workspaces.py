from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.domain import Workspace, WorkspaceMember, User
from app.schemas.domain import WorkspaceCreate, InviteData

router = APIRouter()

@router.get("/dashboard")
def get_dashboard(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_id = current_user['user_id']
    # Получаем все группы, в которых состоит пользователь
    workspaces = db.query(Workspace).join(WorkspaceMember).filter(WorkspaceMember.user_id == user_id).order_by(Workspace.id).all()
    
    result = []
    for ws in workspaces:
        ws_dict = {
            "id": ws.id, 
            "name": ws.name, 
            "owner_id": ws.owner_id, 
            "is_owner": str(ws.owner_id) == str(user_id), 
            "servers": [], 
            "members": []
        }
        
        for s in ws.servers:
            if s.status == 'archived': 
                continue
            
            is_creator = str(s.creator_id) == str(user_id)
            can_view_agent = is_creator or (ws_dict["is_owner"] and s.delegated_can_view_agent)
            
            ws_dict["servers"].append({
                "id": s.id, 
                "hostname": s.hostname, 
                "ip_address": str(s.ip_address),
                "status": s.status, 
                "creator_id": s.creator_id, 
                "is_creator": is_creator,
                "can_delete": is_creator or (ws_dict["is_owner"] and s.delegated_can_delete),
                "can_rename": is_creator or (ws_dict["is_owner"] and s.delegated_can_rename),
                "can_view_agent": can_view_agent,
                "agent_token": str(s.agent_token) if can_view_agent else ""
            })
            
        for m in ws.members:
            ws_dict["members"].append({
                "id": m.user.id, 
                "username": m.user.username, 
                "email": m.user.email
            })
            
        result.append(ws_dict)
    return result

@router.post("/workspaces")
def create_workspace(data: WorkspaceCreate, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    # Защита от спама (Anti-DDoS / Rate Limiting на уровне бизнес-логики)
    today_count = db.query(Workspace).filter(Workspace.owner_id == current_user['user_id']).count()
    if today_count >= 10:
        raise HTTPException(status_code=400, detail="Лимит: не более 10 групп.")
        
    if db.query(Workspace).filter(Workspace.name == data.name, Workspace.owner_id == current_user['user_id']).first():
        raise HTTPException(status_code=400, detail="Группа с таким названием уже существует")

    new_ws = Workspace(name=data.name, owner_id=current_user['user_id'])
    db.add(new_ws)
    db.commit()
    db.refresh(new_ws)
    
    db.add(WorkspaceMember(workspace_id=new_ws.id, user_id=current_user['user_id']))
    db.commit()
    return {"status": "ok"}

@router.put("/workspaces/{ws_id}")
def rename_workspace(ws_id: int, data: WorkspaceCreate, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    ws = db.query(Workspace).filter(Workspace.id == ws_id, Workspace.owner_id == current_user['user_id']).first()
    if not ws: 
        raise HTTPException(status_code=403, detail="Только владелец может переименовать группу")
    
    ws.name = data.name
    db.commit()
    return {"status": "ok"}

@router.delete("/workspaces/{ws_id}")
def delete_workspace(ws_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    ws = db.query(Workspace).filter(Workspace.id == ws_id, Workspace.owner_id == current_user['user_id']).first()
    if not ws: 
        raise HTTPException(status_code=403, detail="Только владелец может удалить группу")
    
    db.delete(ws)
    db.commit()
    return {"status": "ok"}

@router.delete("/workspaces/{ws_id}/leave")
def leave_workspace(ws_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    ws = db.query(Workspace).filter(Workspace.id == ws_id).first()
    if not ws: 
        raise HTTPException(status_code=404, detail="Группа не найдена")
    
    if str(ws.owner_id) == str(current_user['user_id']):
        raise HTTPException(status_code=400, detail="Владелец не может покинуть группу.")
        
    db.query(WorkspaceMember).filter(WorkspaceMember.workspace_id == ws_id, WorkspaceMember.user_id == current_user['user_id']).delete()
    db.commit()
    return {"status": "ok"}

@router.delete("/workspaces/{ws_id}/members/{target_user_id}")
def remove_member(ws_id: int, target_user_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    ws = db.query(Workspace).filter(Workspace.id == ws_id).first()
    if not ws or str(ws.owner_id) != str(current_user['user_id']): 
        raise HTTPException(status_code=403, detail="Только владелец может удалять")
    if str(ws.owner_id) == str(target_user_id): 
        raise HTTPException(status_code=400, detail="Нельзя удалить самого себя")
        
    db.query(WorkspaceMember).filter(WorkspaceMember.workspace_id == ws_id, WorkspaceMember.user_id == target_user_id).delete()
    db.commit()
    return {"status": "ok"}

@router.post("/team/invite")
def invite_to_team(data: InviteData, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    ws = db.query(Workspace).filter(Workspace.id == data.workspace_id).first()
    if not ws or str(ws.owner_id) != str(current_user['user_id']): 
        raise HTTPException(status_code=403, detail="Только создатель может приглашать")
    
    clean_username = data.username.replace('@', '').strip()
    target_user = db.query(User).filter(User.username == clean_username).first()
    if not target_user: 
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if str(target_user.id) == str(current_user['user_id']): 
        raise HTTPException(status_code=400, detail="Вы не можете добавить самого себя")
    
    if db.query(WorkspaceMember).filter(WorkspaceMember.workspace_id == data.workspace_id, WorkspaceMember.user_id == target_user.id).first():
        raise HTTPException(status_code=400, detail="Уже в группе")
        
    db.add(WorkspaceMember(workspace_id=data.workspace_id, user_id=target_user.id))
    db.commit()
    return {
        "status": "ok", 
        "message": "Добавлен", 
        "invite_link": f"https://inv.e-laba52.ru/?team_invite={data.workspace_id}"
    }
