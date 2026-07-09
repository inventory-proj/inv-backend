from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Импортируем наши новые защищенные модульные роутеры
from app.api.routers import auth, workspaces, servers, admin

app = FastAPI(title="SaaS Security API", version="3.0")

# БЕЗОПАСНОСТЬ: Сейчас стоит ["*"], чтобы ты мог зайти и протестировать код.
# На Этапе 3 мы жестко пропишем здесь домен твоего сайта для защиты от CSRF.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Подключение модульных роутеров к основному приложению
app.include_router(auth.router, prefix="/api", tags=["Authentication"])
app.include_router(workspaces.router, prefix="/api", tags=["Workspaces"])
app.include_router(servers.router, prefix="/api", tags=["Servers"])
app.include_router(admin.router, prefix="/api/admin", tags=["Global Admin"])

@app.get("/health")
def health_check():
    return {"status": "ok", "message": "Backend modular architecture is ready"}
