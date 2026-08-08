FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY policies ./policies
COPY consul ./consul
COPY src ./src
COPY VERSION .

RUN useradd -m -u 10001 appuser && chown -R appuser:appuser /app
USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "from core.health import assert_healthy; assert_healthy()"

# Control-plane library; default command validates health and keeps process semantics explicit.
CMD ["python", "-c", "from core.health import check; import json; print(json.dumps(check()))"]
