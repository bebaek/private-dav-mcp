FROM python:3.11-slim

COPY --from=ghcr.io/astral-sh/uv:0.11.29 /uv /uvx /bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:${PATH}"

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --create-home app

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY private_dav_mcp ./private_dav_mcp
RUN uv sync --frozen --no-dev

RUN chown -R app:app /app
USER app

EXPOSE 8767 8768

CMD ["private-dav-carddav-mcp", "--host", "0.0.0.0", "--port", "8767"]
