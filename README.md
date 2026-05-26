# Security Checker MCP Server

Security Checker is an MCP server for guideline-based application security review. It exposes a small stateless tool surface for:

- classifying in-memory files and detecting hardcoded secrets in one pass
- semantically searching a security-guideline knowledge base
- finalizing a markdown report for the client to save

The server is built around 150 internal security development guidelines across 12 domains, indexed into ChromaDB from `knowledge/chunks/guidelines_chunks.json`.

## What the Project Actually Does

The current server exposes:

- 3 tools
- 3 resources
- 3 prompts

It does not read files from disk on behalf of the client during review. The client is expected to collect file contents, send them to `scan`, inspect suspicious patterns, use `search_guidelines` for targeted lookups, and then call `save_report` to finalize the report text.

## Exposed MCP Surface

### Tools

| Tool | What it does | Notes |
|------|---------------|-------|
| `scan(files, include_numbered=false)` | Classifies forwarded files and runs deterministic secret detection in a single stateless call | Input is a list of `{path, content}` objects; returns manifest, redacted secret findings, and skipped files |
| `search_guidelines(query, domain_code="", language="", top_k=5)` | Searches the guideline KB with semantic retrieval and optional filters | Returns matched guideline IDs, domains, requirement text, and relevance |
| `save_report(content, filename="security_report.md")` | Finalizes a markdown report with metadata | Returns JSON containing the suggested filename and full report text; the client writes it to disk |

### Resources

| Resource | What it returns |
|----------|------------------|
| `guidelines://domains` | The 12 guideline domains and counts |
| `guidelines://summary` | Overview of the framework and recommended workflow |
| `guidelines://{domain_code}` | All guideline chunks for one domain |

### Prompts

| Prompt | Purpose |
|--------|---------|
| `security_review(target_description)` | Full multi-step review workflow using `scan`, `search_guidelines`, and `save_report` |
| `quick_file_review(file_path)` | Single-file review flow |
| `secrets_audit(target_description)` | Secret-focused review flow over `scan` results |

## Review Workflow

The intended review model is:

1. The client gathers file contents and sends them to `scan`.
2. The reviewer inspects the returned manifest and secret findings.
3. For suspicious code patterns, the reviewer calls `search_guidelines` with targeted queries, domain filters, and language hints.
4. The reviewer builds a guideline-backed report.
5. The reviewer calls `save_report` and writes the returned report text to disk.

This is deliberately compliance-oriented rather than a general-purpose SAST engine. The toolchain is optimized for reproducible, guideline-cited reviews instead of autonomous repository crawling.

## Security Domains

The knowledge base covers these 12 domains:

- `SM` Session Management
- `AU` Authentication
- `AZ` Authorization
- `IV` Input Validation and Output Encoding
- `XS` Cross-Site Scripting
- `AP` API Security
- `CR` Cryptography and Secrets
- `EL` Error Handling and Logging
- `SH` Security Headers
- `FU` File Upload Security
- `DS` Dependency and Supply Chain
- `DP` Data Protection and Privacy

All 150 guidelines are treated as CRITICAL severity.

## Stateless Scan Model

`scan` is the main entry point for reviews. It consolidates classification and secret scanning into a single stateless call over in-memory file contents.

Behavior:

- classifies each forwarded file by path into types such as `source_code`, `config`, and `dependency_manifest`
- assigns applicable guideline domains per file
- scans text deterministically for hardcoded secrets using regex patterns
- redacts secret evidence in the returned findings
- optionally returns numbered file content when `include_numbered=true`
- reports oversized or malformed entries in `skipped`

Limits:

- per-call batch limit: about 6 MB of combined file content
- per-file limit: about 1 MB
- oversized batches return `payload_too_large` with recovery guidance
- binary, media, lock, and minified assets should be excluded by the caller before sending

The bundled fixtures in `tests/fixtures` exercise this path and intentionally include insecure examples.

## Knowledge Base

Guideline chunks live in `knowledge/chunks/guidelines_chunks.json`. The builder script enriches them and writes a persistent ChromaDB collection named `security_guidelines` under `knowledge/chroma_store`.

Build the KB with:

```bash
python -m security_checker.scripts.build_kb --rebuild --verify
```

What the builder does:

- loads the JSON guideline chunks
- enriches documents with domain, section, detection-hint, and language metadata
- creates or rebuilds the Chroma collection
- optionally runs verification queries against expected guideline IDs

The server fails fast at startup if the knowledge base has not been built.

## Embeddings

Embedding resolution is currently:

1. ChromaDB ONNX MiniLM
2. deterministic hash-based fallback

The README previously implied `sentence-transformers` support, but the current code has removed it. ONNX is the preferred path; the hash fallback keeps the server usable when ONNX is unavailable, but search quality drops to approximate exact-term matching.

## Transport Modes

Transport is selected at runtime with `MCP_TRANSPORT`:

- `stdio` is the default for local MCP clients such as VS Code, Cursor, and Claude Desktop
- `http` enables a stateless Streamable HTTP endpoint

### Stdio mode

Run locally with any of:

```bash
security-checker-mcp
```

```bash
python -m security_checker.mcp_server
```

```bash
mcp dev src/security_checker/mcp_server.py
```

### HTTP mode

HTTP mode serves the MCP endpoint at `/mcp` and an unauthenticated health check at `/healthz`.

Environment variables:

- `MCP_TRANSPORT=http`
- `MCP_HOST` default `127.0.0.1`
- `MCP_PORT` default `8000`
- `MCP_AUTH_TOKEN` required unless `MCP_ALLOW_UNAUTHENTICATED=1`

The HTTP wrapper also:

- enforces bearer-token auth on the MCP endpoint
- normalizes `/mcp/` to `/mcp` to avoid redirect issues
- refuses to start without authentication unless explicitly allowed

## Installation

### Requirements

- Python `>=3.10,<3.14`
- `uv` is convenient but not required

### Local setup

```bash
uv venv
source .venv/bin/activate
uv pip install -e .
python -m security_checker.scripts.build_kb --rebuild --verify
```

## MCP Client Configuration

### VS Code over stdio

```json
{
  "servers": {
    "security-checker": {
      "type": "stdio",
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/security-checker-mcp",
        "python",
        "-m",
        "security_checker.mcp_server"
      ]
    }
  }
}
```

### VS Code over HTTP

```json
{
  "servers": {
    "security-checker": {
      "type": "http",
      "url": "http://localhost:8000/mcp",
      "headers": {
        "Authorization": "Bearer ${input:scToken}"
      }
    }
  },
  "inputs": [
    {
      "id": "scToken",
      "type": "promptString",
      "description": "Security Checker token",
      "password": true
    }
  ]
}
```

### Cursor or Claude Desktop

```json
{
  "mcpServers": {
    "security-checker": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/security-checker-mcp",
        "python",
        "-m",
        "security_checker.mcp_server"
      ]
    }
  }
}
```

## Docker and Deployment

The container image is HTTP-first.

The Docker build:

- installs the package
- copies `src` and `knowledge`
- builds the Chroma knowledge base during image build
- defaults to `MCP_TRANSPORT=http`, `MCP_HOST=0.0.0.0`, and port `8000`

Local container run:

```bash
docker build --platform linux/amd64 -t security-checker-mcp .
docker run --rm -p 8000:8000 -e MCP_AUTH_TOKEN=local-poc-token security-checker-mcp
```

There is also a smoke test at `scripts/http_smoke_test.py` that:

- lists tools and prompts from a running HTTP server
- scans the bundled vulnerable fixtures
- verifies the batch-overflow path returns `payload_too_large`

For the full deployment walkthrough, see `DEPLOYMENT.md`.

## Tests

The regression tests live in `tests/test_scan.py`. They verify:

- path-based classification matches the legacy disk scanner
- in-memory secret findings match the legacy disk scanner
- the consolidated `scan` result shape and counts
- per-file oversize skipping
- per-batch overflow self-correction
- secret evidence redaction

Run them with:

```bash
pytest
```

## Repository Layout

```text
src/security_checker/
  mcp_server.py           MCP server definition, transport handling, prompts
  embedding_utils.py      Embedding backend resolver
  limits.py               Batch and per-file size ceilings
  tools/
    scan.py               Stateless one-shot scan entry point
    file_scanner.py       Path-based classification heuristics
    guideline_search.py   ChromaDB-backed guideline retrieval
    secret_scanner.py     Regex-based secret detection
    file_reader.py        Line-numbering helper used by optional scan output
  scripts/
    build_kb.py           Knowledge-base builder

knowledge/
  chunks/
    guidelines_chunks.json
  chroma_store/
    ... persisted ChromaDB collection ...

tests/
  fixtures/
    ... intentionally vulnerable sample files ...
  test_scan.py
```

### `search_guidelines`

- Queries the ChromaDB collection with a natural-language search string
- Accepts optional `domain_code` and `language` hints
- Uses the domain filter as exact metadata matching
- Appends the language to the search query for better retrieval
- Caps `top_k` at 20 results

The output is formatted text intended for an agent to read, not structured JSON.

### `save_report`

- Writes the provided markdown report to disk
- Resolves relative output paths against the current working directory
- Creates parent directories if needed
- Prepends generation metadata comments to the file

This is the final step in the built-in review prompts.

## Prompt Workflows

### `security_review`

This is the main end-to-end workflow. It instructs the MCP client to:

1. discover files with `scan_files`
2. run `scan_secrets`
3. inspect each source and config file with `read_file`
4. search for relevant requirements with `search_guidelines`
5. synthesize and save a complete compliance report with `save_report`

It also encodes review rules such as:

- every finding should cite a guideline ID when possible
- clearly exploitable unmatched issues may be reported as `UG-xxx`
- context matters for test code vs production code

### `quick_file_review`

This prompt is optimized for a single file. It combines a line-numbered read, a secret scan, targeted KB lookup, and a required final report save.

### `secrets_audit`

This prompt is focused on secret exposure. It tells the reviewing agent to parse the JSON returned by `scan_secrets`, render findings as a table, map them all to `CR-05.1`, and provide remediation guidance based on secret type.

## Test Fixtures

The repository includes intentionally vulnerable fixtures under `tests/fixtures/` for exercising the tools and prompt workflows.

- `.env.test` contains multiple hardcoded secrets and credentials
- `nginx.conf` contains transport, CORS, and header misconfigurations
- `vulnerable_app.py` contains representative application-security violations such as weak password hashing, SQL injection, command injection, unsafe deserialization, insecure session handling, reflected XSS, and hardcoded secrets
- `package.json` is present as a dependency manifest fixture

These files are useful for testing both the tools and the agent prompts end to end.

## Current Constraints

- The knowledge base must be built before the server starts
- File scanning and reading skip files larger than 500 KB
- Secret scanning skips common binary and minified asset extensions
- Search quality depends on the embedding backend available at runtime
- File classification is heuristic rather than parser-based
- `search_guidelines` returns formatted text, so callers need to interpret the results

## Typical Usage Pattern

For a full directory review, the intended order is:

1. `scan_files`
2. `scan_secrets`
3. `read_file` for each relevant file
4. `search_guidelines` for each suspicious pattern
5. `save_report`

That flow is exactly what the built-in `security_review` prompt automates.
