# Deployment Guide (POC)

The same container image you test locally is the artifact you push to AWS, so
"works in Docker locally" is strong evidence it works on App Runner. Validate
locally first, then deploy.

---

## 1. Test locally with Docker

### Build (target the architecture AWS runs — required on Apple Silicon)

```bash
docker build --platform linux/amd64 -t security-checker-mcp .
```

The build runs `build_kb` so the ChromaDB knowledge base and the embedding
model are baked into the image (instant startup, no runtime downloads).

### Run

```bash
docker run --rm -p 8000:8000 \
  -e MCP_AUTH_TOKEN=local-poc-token \
  security-checker-mcp
```

The MCP endpoint is at `http://localhost:8000/mcp`; health at `/healthz`.
`MCP_HOST=0.0.0.0` is set in the image so the published port reaches the server.

### Smoke-test it

```bash
# quick raw checks
curl http://localhost:8000/healthz                      # {"status":"ok"}
curl -i -X POST http://localhost:8000/mcp -d '{}'        # 401 (no token)

# full client test (lists tools, scans fixtures, checks overflow)
pip install "mcp>=1.12"
MCP_URL=http://localhost:8000/mcp MCP_AUTH_TOKEN=local-poc-token \
  python scripts/http_smoke_test.py
```

### Drive it with VS Code Copilot (the real proof)

Create `.vscode/mcp.json` in any workspace. **The root key is `servers`** (not
`mcpServers` — that key is for Cursor/Claude Desktop and is the #1 setup
mistake). Use an input variable so the token isn't hardcoded:

```json
{
  "servers": {
    "security-checker": {
      "type": "http",
      "url": "http://localhost:8000/mcp",
      "headers": { "Authorization": "Bearer ${input:scToken}" }
    }
  },
  "inputs": [
    { "id": "scToken", "type": "promptString", "description": "Security Checker token", "password": true }
  ]
}
```

Then open Copilot Chat and **switch to Agent mode** — MCP tools are invisible in
Ask/Edit mode. Confirm Copilot sees the `scan` tool, reads the batching hint in
its description, and recovers from `payload_too_large` on a large repo. (If your
org has Copilot Business/Enterprise, the "MCP servers in Copilot" policy must be
enabled.)

### Optional: rehearse the HTTPS edge before AWS

Local testing uses plain HTTP; App Runner serves HTTPS and terminates TLS at its
edge. To flush out the proxy-only behaviors (the `/mcp/` trailing-slash and
header-forwarding cases) before deploying, uncomment the `caddy` service in
`docker-compose.yml`, add a `Caddyfile`:

```
localhost {
    reverse_proxy security-checker:8000
}
```

then `docker compose up --build` and point Copilot at `https://localhost/mcp`.

---

## 2. Deploy to AWS App Runner (POC)

App Runner is the lowest-friction path: give it a container image and it provides
HTTPS, scaling, and health checks. Our stateless server is exactly the shape it
wants.

> Verify current App Runner instance sizes, request-timeout, and pricing in the
> AWS console — those specifics change.

### a. Push the image to ECR

```bash
AWS_REGION=ap-south-1                      # your region
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REPO=$ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com/security-checker-mcp

aws ecr create-repository --repository-name security-checker-mcp --region $AWS_REGION
aws ecr get-login-password --region $AWS_REGION \
  | docker login --username AWS --password-stdin $ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com

docker build --platform linux/amd64 -t $REPO:latest .
docker push $REPO:latest
```

### b. Create the App Runner service

Console (App Runner → Create service → Container registry → your ECR image), or
CLI. Configure:

- **Port:** `8000`
- **Environment variables:** `MCP_AUTH_TOKEN` = a strong shared token.
  (`MCP_TRANSPORT=http`, `MCP_HOST=0.0.0.0`, `MCP_PORT=8000` are already image
  defaults.)
- **Health check:** HTTP, path `/healthz` (NOT `/` — and not `/mcp`, which needs
  a POST + MCP handshake).
- **Instance size:** ~1 vCPU / 2 GB is ample (ChromaDB + MiniLM embeddings +
  a single ≤6 MB request).

App Runner gives you `https://<id>.<region>.awsapprunner.com`. Your MCP endpoint
is that URL + `/mcp`.

### c. Verify and connect

```bash
MCP_URL=https://<id>.<region>.awsapprunner.com/mcp MCP_AUTH_TOKEN=<token> \
  python scripts/http_smoke_test.py
```

Then update `.vscode/mcp.json` `url` to the App Runner URL and distribute the
token to your developers.

### Tightening / graduation (post-POC)

- Replace the shared token with per-developer tokens or OAuth 2.1.
- Make the endpoint private (App Runner VPC ingress) if it must be off the public
  internet — note developers then need VPN into the VPC.
- For perimeter controls (WAF, private subnets) or higher scale, move to ECS
  Fargate behind an ALB. Because the server is stateless, that is an infra change
  only — no code change, no sticky sessions.

---

## Configuration reference

| Env var          | Default     | Purpose                                      |
|------------------|-------------|----------------------------------------------|
| `MCP_TRANSPORT`  | `stdio`     | `http` for the container; `stdio` for local IDE subprocess |
| `MCP_HOST`       | `127.0.0.1` | `0.0.0.0` in containers (set in image)       |
| `MCP_PORT`       | `8000`      | Listen port                                  |
| `MCP_AUTH_TOKEN` | _(unset)_   | Bearer token for `/mcp`. **Required in `http` mode** — the server refuses to start without it. |
| `MCP_ALLOW_UNAUTHENTICATED` | _(unset)_ | Set to `1` to run `http` mode with NO auth on purpose (local testing only). Do not set this on App Runner. |

**Fail-closed:** in `http` mode the server exits on startup unless `MCP_AUTH_TOKEN`
is set, so you cannot accidentally publish an open endpoint. To run open
deliberately for local testing, set `MCP_ALLOW_UNAUTHENTICATED=1`. For local-only
exposure regardless of auth, publish to loopback with `-p 127.0.0.1:8000:8000`.

Size limits live in `src/security_checker/limits.py`: per-file 1 MB,
per-call (batch) 6 MB.