# Сборка зависимостей
FROM dockerhub.timeweb.cloud/library/python:3.11-slim AS builder
WORKDIR /build

RUN sed -i 's/deb.debian.org/mirror.yandex.ru/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || sed -i 's/deb.debian.org/mirror.yandex.ru/g' /etc/apt/sources.list
RUN apt-get update && apt-get install -y libpq-dev gcc && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt .

RUN pip wheel --no-cache-dir --wheel-dir /build/wheels -r requirements.txt

# Боевой образ (Runner)
FROM dockerhub.timeweb.cloud/library/python:3.11-slim AS runner
WORKDIR /opt/project

RUN sed -i 's/deb.debian.org/mirror.yandex.ru/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || sed -i 's/deb.debian.org/mirror.yandex.ru/g' /etc/apt/sources.list
RUN apt-get update && apt-get install -y libpq5 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/wheels /wheels
COPY --from=builder /build/requirements.txt .

RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt

RUN addgroup --system --gid 1001 fastapi && \
    adduser --system --uid 1001 --gid 1001 fastapi

COPY app/ /opt/project/app/
RUN chown -R fastapi:fastapi /opt/project

USER fastapi
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
