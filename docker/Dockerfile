# Multi-stage build: build the SPA, then run the FastAPI backend serving it.
FROM node:22-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim AS runtime
WORKDIR /app

# System deps: nmap is optional (engine works without it); curl for healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY backend/ ./backend/
COPY scanner/ ./scanner/
COPY vuln_engine/ ./vuln_engine/
RUN pip install --no-cache-dir .

# Built SPA from the frontend stage (served at / by the backend).
COPY --from=frontend /app/frontend/dist ./frontend/dist

ENV SENTINEL_HOST=0.0.0.0 \
    SENTINEL_PORT=8787 \
    SENTINEL_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -fsS http://127.0.0.1:8787/api/health || exit 1

CMD ["sentinelscan"]
