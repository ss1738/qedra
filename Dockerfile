# Runs the qedra MCP server over stdio. Used by MCP hosts and by Glama's
# introspection check (the server starts and responds to a list-tools request).
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git bash ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY qedra ./qedra
COPY integrations ./integrations

RUN pip install --no-cache-dir uv==0.11.14 \
    && uv sync --frozen --no-dev --extra mcp --python /usr/local/bin/python3

ENV GUARDRAIL_WORKSPACE=/workspace \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 qedra \
    && mkdir -p /workspace \
    && chown qedra:qedra /workspace
USER qedra

# stdio MCP server
CMD ["qedra-mcp"]
