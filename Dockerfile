# Security Checker MCP — HTTP server image
#
# Build (target the architecture App Runner / Fargate run — important on Apple Silicon):
#   docker build --platform linux/amd64 -t security-checker-mcp .
#
# Run locally:
#   docker run --rm -p 8000:8000 \
#     -e MCP_AUTH_TOKEN=local-poc-token \
#     security-checker-mcp
#
# The MCP endpoint is then at http://localhost:8000/mcp  (health: /healthz)

FROM python:3.12-slim

# System deps occasionally needed by chromadb/onnxruntime wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the package first (layer caching), then copy source
COPY pyproject.toml ./
COPY src ./src
COPY knowledge ./knowledge
RUN pip install --no-cache-dir -e .

# Build the ChromaDB knowledge base at image-build time so:
#   - startup is instant (no "KB missing" failure path in the POC)
#   - the embedding model is cached inside the image (no runtime download)
#   - the persisted store and the runtime embedding backend always match
RUN python -m security_checker.scripts.build_kb --rebuild --verify

# HTTP transport defaults. MCP_HOST must be 0.0.0.0 inside a container so the
# published port reaches the server. Override MCP_AUTH_TOKEN at run time.
ENV MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# Container-level health check hits the unauthenticated /healthz endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=3).status==200 else 1)"

CMD ["security-checker-mcp"]
