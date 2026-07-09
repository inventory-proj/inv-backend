from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.orm import Session
import json
from app.core.database import get_db
from app.core.security import require_global_admin
from app.models.domain import User, Server

router = APIRouter()

@router.get("/users")
def get_all_users(current_user: dict = Depends(require_global_admin), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.id).all()
    return [{"id": u.id, "username": u.username, "email": u.email, "role_name": u.role.role_name if u.role else "viewer"} for u in users]

@router.get("/export")
def export_database(current_user: dict = Depends(require_global_admin), db: Session = Depends(get_db)):
    servers = db.query(Server).all()
    data = [{"id": s.id, "hostname": s.hostname, "ip_address": str(s.ip_address), "status": s.status} for s in servers]
    json_str = json.dumps({"servers": data}, indent=4, ensure_ascii=False)
    return Response(content=json_str, media_type="application/json", headers={"Content-Disposition": "attachment; filename=backup.json"})
