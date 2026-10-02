# syntax=docker/dockerfile:1.7
# The gateway image: a non-root, venv-only runtime with no build tooling.

FROM ghcr.io/astral-sh/uv:0.12-python3.12-trixie-slim AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0
WORKDIR /app
# Dependencies first, so source edits do not invalidate this layer.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=demo/pyproject.toml,target=demo/pyproject.toml \
    uv sync --locked --no-dev --no-install-workspace --package mcp-customs
COPY pyproject.toml uv.lock README.md ./
COPY demo/pyproject.toml demo/pyproject.toml
COPY src src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable --package mcp-customs

FROM python:3.12-slim-trixie
RUN groupadd --system customs && useradd --system --gid customs --no-create-home customs
COPY --from=build --chown=customs:customs /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
USER customs
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
ENTRYPOINT ["customs"]
CMD ["run", "--config", "/etc/customs/customs.yaml", "--host", "0.0.0.0"]
