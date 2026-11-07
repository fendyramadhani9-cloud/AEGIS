# syntax=docker/dockerfile:1
# ============================================================================
# AEGIS Backend Gateway & AI Investigation Engine — Ultra-Low RAM Dockerfile
# Base: python:3.12-slim (~55-75 MB RAM idle, ~95 MB active with 1 worker)
# Listens on Dedicated Port 1709 (Proxied via Dashboard Port 1708)
# ============================================================================

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONOPTIMIZE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    API_HOST=0.0.0.0 \
    API_PORT=1709 \
    AEGIS_STATE_FILE=/app/data/.aegis_operational_state.json

WORKDIR /app

# Create non-root service account & state directory
RUN groupadd -g 10001 aegis && \
    useradd -u 10001 -g aegis -s /sbin/nologin -M aegis && \
    mkdir -p /app/data && \
    chown -R aegis:aegis /app

# Install runtime Python dependencies (excluding pytest to save image & memory footprint)
COPY requirements.txt ./
RUN grep -vE '^(pytest)' requirements.txt > requirements.prod.txt && \
    pip install --no-cache-dir -r requirements.prod.txt && \
    rm -f requirements.prod.txt

# Copy backend & agent packages
COPY --chown=aegis:aegis aegis_backend ./aegis_backend
COPY --chown=aegis:aegis aegis_agent ./aegis_agent
COPY --chown=aegis:aegis main.py ./main.py

USER aegis

EXPOSE 1709

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:1709/api/health', timeout=3)" || exit 1

CMD ["python", "-m", "uvicorn", "aegis_backend.main:app", "--host", "0.0.0.0", "--port", "1709", "--workers", "1", "--no-access-log"]
