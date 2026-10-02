# syntax=docker/dockerfile:1.7
# One image for the demo: both sample MCP servers and the scripted agent.

FROM ghcr.io/astral-sh/uv:0.12-python3.12-trixie-slim AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0
WORKDIR /app
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=demo/pyproject.toml,target=demo/pyproject.toml \
    uv sync --locked --no-dev --no-install-workspace --package customs-demo
COPY pyproject.toml uv.lock README.md ./
COPY demo demo
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable --package customs-demo

FROM python:3.12-slim-trixie
RUN groupadd --system demo && useradd --system --gid demo --no-create-home demo \
    && mkdir /tokens && chown demo:demo /tokens
COPY --from=build --chown=demo:demo /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 HOST=0.0.0.0
USER demo
