from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, text
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    role_name = Column(String(50), unique=True, nullable=False)
    users = relationship("User", back_populates="role")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"))
    
    # Флаг для микросервиса Email (подтверждение почты)
    is_verified = Column(Boolean, default=False)
    
    role = relationship("Role", back_populates="users")
    owned_workspaces = relationship("Workspace", back_populates="owner", cascade="all, delete-orphan")
    workspaces = relationship("WorkspaceMember", back_populates="user", cascade="all, delete-orphan")

class Workspace(Base):
    __tablename__ = "workspaces"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    owner = relationship("User", back_populates="owned_workspaces")
    members = relationship("WorkspaceMember", back_populates="workspace", cascade="all, delete-orphan")
    servers = relationship("Server", back_populates="workspace", cascade="all, delete-orphan")

class WorkspaceMember(Base):
    __tablename__ = "workspace_members"
    workspace_id = Column(Integer, ForeignKey("workspaces.id", ondelete="CASCADE"), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    
    workspace = relationship("Workspace", back_populates="members")
    user = relationship("User", back_populates="workspaces")

class Server(Base):
    __tablename__ = "servers"
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False)
    ip_address = Column(INET, nullable=False)
    cluster_id = Column(Integer, ForeignKey("clusters.id", ondelete="SET NULL"), nullable=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id", ondelete="CASCADE"))
    creator_id = Column(Integer, ForeignKey("users.id"))
    
    # Флаги гранулярного делегирования прав (RBAC)
    delegated_can_delete = Column(Boolean, default=False)
    delegated_can_rename = Column(Boolean, default=False)
    delegated_can_view_agent = Column(Boolean, default=False)
    
    # Токен агента генерируется базой данных автоматически через UUID
    agent_token = Column(UUID(as_uuid=True), server_default=text("gen_random_uuid()"), unique=True)
    status = Column(String(20), default="active")
    
    workspace = relationship("Workspace", back_populates="servers")
