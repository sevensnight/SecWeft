FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VULNLAB_DB_PATH=/data/vulnlab.db \
    VULNLAB_WORKSPACE_ROOT=/data/workspaces

WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY pyproject.toml README.md ./
COPY apps/control-plane/src ./apps/control-plane/src
COPY apps/validation-worker ./apps/validation-worker
COPY solve_module2.py ./
COPY solve_p12_disaster_recovery.py solve_p12_scale.py solve_p12_chaos.py ./
RUN pip install --no-cache-dir --no-deps .

RUN adduser -D -u 10001 appuser \
    && mkdir -p /data/workspaces \
    && chown -R appuser:appuser /data
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"
CMD ["python", "solve_module2.py", "serve", "--host", "0.0.0.0", "--port", "8000"]
