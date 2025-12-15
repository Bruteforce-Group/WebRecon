FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_NO_PROGRESS=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /app

# Install uv (used both for dependency resolution and for deterministic sync via uv.lock)
RUN pip install --no-cache-dir uv==0.9.16

# Install runtime dependencies into /opt/venv using uv.lock for reproducibility
COPY pyproject.toml uv.lock /app/
RUN uv sync --frozen --no-dev --no-install-project

COPY webrecon.py /app/webrecon.py

# Non-root runtime user
RUN useradd -m -u 10001 app && \
    mkdir -p /app/webrecon_output && \
    chown -R app:app /app /opt/venv

USER app

ENTRYPOINT ["/opt/venv/bin/python", "/app/webrecon.py"]


