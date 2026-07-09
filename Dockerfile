# Сборка зависимостей
FROM dockerhub.timeweb.cloud/library/python:3.11-slim AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y libpq-dev gcc && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt .

RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

# Runner (Боевой образ)
FROM dockerhub.timeweb.cloud/library/python:3.11-slim AS runner
WORKDIR /app

RUN apt-get update && apt-get install -y libpq5 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/wheels /wheels
COPY --from=builder /app/requirements.txt .
RUN pip install --no-cache /wheels/*

RUN addgroup --system --gid 1001 fastapi && \
    adduser --system --uid 1001 --gid 1001 fastapi

COPY app/ /app/

RUN chown -R fastapi:fastapi /app

USER fastapi

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
