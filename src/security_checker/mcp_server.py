"""Security Checker MCP Server (stateless HTTP-ready).

Exposes a consolidated, stateless tool surface for AI-assisted security
guidelines compliance review:

  Tools     : scan, search_guidelines, save_report
  Resources : guidelines://domains, guidelines://summary, guidelines://{code}
  Prompts   : security_review, quick_file_review, secrets_audit

Transport is selected at runtime:
    MCP_TRANSPORT=stdio   (default)  — local subprocess, for VS Code/Cursor/Claude Desktop
    MCP_TRANSPORT=http               — Streamable HTTP, for remote/containerized use

HTTP mode adds a bearer-token gate and a /healthz endpoint, and serves the
MCP endpoint at /mcp (stateless, JSON responses).
"""

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
import json
import os
import sys

from mcp.server.fastmcp import FastMCP

from security_checker.limits import BATCH_MAX_BYTES, PER_FILE_MAX_BYTES, mb


# ─── Lifespan Context ─────────────────────────────────────────────

@dataclass
class AppContext:
    """Server-wide resources initialized on startup."""
    guidelines_chunks: list[dict] = field(default_factory=list)
    domain_index: dict[str, list[dict]] = field(default_factory=dict)


@asynccontextmanager
async def server_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Initialize resources on startup, verify knowledge base exists."""

    project_root = Path(__file__).resolve().parent.parent.parent
    chroma_dir = project_root / "knowledge" / "chroma_store"
    chunks_path = project_root / "knowledge" / "chunks" / "guidelines_chunks.json"

    # ── Fail fast if knowledge base hasn't been built ──
    if not chroma_dir.exists() or not any(chroma_dir.iterdir()):
        print(
            "ERROR: Knowledge base not found.\n"
            "Run: python -m security_checker.scripts.build_kb --rebuild\n",
            file=sys.stderr,
        )
        raise RuntimeError("Knowledge base not found. Build it first.")

    # ── Load guideline chunks for resources ──
    if chunks_path.exists():
        with open(chunks_path) as f:
            data = json.load(f)
        chunks = data.get("chunks", [])
    else:
        chunks = []

    # ── Build domain index for fast resource lookups ──
    domain_index: dict[str, list[dict]] = {}
    for chunk in chunks:
        domain_index.setdefault(chunk["domain_code"], []).append(chunk)

    print(f"[security-checker] Loaded {len(chunks)} guidelines across {len(domain_index)} domains", file=sys.stderr)

    yield AppContext(
        guidelines_chunks=chunks,
        domain_index=domain_index,
    )


# ─── Create Server ────────────────────────────────────────────────
# stateless_http + json_response are HTTP-only settings (ignored in stdio).
# They make the Streamable HTTP endpoint stateless with plain-JSON responses,
# which is what App Runner / load balancers want.

mcp = FastMCP(
    "security-checker",
    lifespan=server_lifespan,
    stateless_http=True,
    json_response=True,
)


# ═══════════════════════════════════════════════════════════════════
# TOOLS
# ═══════════════════════════════════════════════════════════════════

@mcp.tool()
def scan(files: list[dict], include_numbered: bool = False) -> str:
    """Classify files and detect hardcoded secrets in ONE stateless call.

    The agent forwards file contents directly; the server holds them only
    for the duration of this call and retains nothing afterward. Use this
    as the first step of any review.

    SIZE LIMITS — read before sending:
    - Send at most ~6 MB of combined file content per call (roughly a
      mid-size service or a PR's worth of files).
    - For a larger repository, split the files across MULTIPLE scan calls,
      each under the limit, and combine the results. Findings are
      independent across calls, so batching does not change the outcome.
    - Before sending, EXCLUDE: node_modules, vendor, .venv, dist, build,
      .next, target, *.lock, *.min.js, *.min.css, and binary/media files.
    - If a call exceeds the limit it returns {"error": "payload_too_large"}
      with instructions — split that batch and retry each half.
    - Any single file over ~1 MB is skipped (listed under "skipped") and
      not reviewed.

    Args:
        files: list of {"path": "<relative path>", "content": "<file text>"}.
        include_numbered: if true, also return line-numbered content per file
            (larger response). Usually leave false — you already have the code
            and can number lines yourself for citations.

    Returns JSON with:
        files: classification manifest (path, type, language, applicable_domains)
        secret_findings: redacted hardcoded-secret matches (all map to CR-05.1)
        files_with_secrets, total, total_secret_findings
        skipped: files not reviewed (oversize or missing path), with reasons
    """
    from security_checker.tools.scan import run_scan
    return json.dumps(run_scan(files, include_numbered=include_numbered), indent=2)


@mcp.tool()
def search_guidelines(
    query: str,
    domain_code: str = "",
    language: str = "",
    top_k: int = 5,
) -> str:
    """Search the organization's 150 security development guidelines.

    Performs semantic search over the guideline knowledge base.
    Returns matching guidelines with their ID, domain, full
    requirement text, and relevance score.

    The knowledge base covers 12 domains:
    SM (Session Management), AU (Authentication), AZ (Authorization),
    IV (Input Validation), XS (Cross-Site Scripting), AP (API Security),
    CR (Cryptography & Secrets), EL (Error Handling & Logging),
    SH (Security Headers), FU (File Upload), DS (Dependencies),
    DP (Data Protection).

    Tips for effective queries:
    - Use specific technical terms: "SQL injection parameterized
      queries" not "database security"
    - Combine with domain_code filter to narrow results
    - Include the programming language for language-specific patterns
    - Search for the pattern you observe, not the guideline you want

    Args:
        query: Natural language search (e.g., "password hashing MD5").
        domain_code: Optional domain filter (e.g., "AU", "IV").
        language: Optional language filter (e.g., "python").
        top_k: Number of results (default 5, max 20).
    """
    from security_checker.tools.guideline_search import search_guidelines_db
    return search_guidelines_db(query=query, domain_code=domain_code, language=language, top_k=top_k)


@mcp.tool()
def save_report(content: str, filename: str = "security_report.md") -> str:
    """Finalize a security review report.

    The server does NOT write to disk. It returns the report with
    generation metadata prepended; the CLIENT is responsible for writing
    the returned content to the user's filesystem. Call this as the final
    step of a review.

    Args:
        content: The full markdown report to finalize.
        filename: Suggested filename (basename only; any directory parts
            are stripped). Default: security_report.md.

    Returns JSON with:
        suggested_filename, bytes, lines, report (metadata header + content)
    """
    from datetime import datetime, timezone

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header = (
        "<!-- Security Compliance Report -->\n"
        f"<!-- Generated: {timestamp} -->\n"
        "<!-- Tool: security-checker-mcp -->\n\n"
    )
    report = header + content
    return json.dumps({
        "suggested_filename": Path(filename).name or "security_report.md",
        "bytes": len(report),
        "lines": report.count("\n"),
        "report": report,
    })


# ═══════════════════════════════════════════════════════════════════
# RESOURCES (3)
# ═══════════════════════════════════════════════════════════════════

@mcp.resource("guidelines://domains")
def list_domains() -> str:
    """Complete list of the 12 security guideline domains."""
    return (
        "Security Guideline Domains\n"
        "==========================\n\n"
        "Code | Domain                          | Guidelines\n"
        "-----|----------------------------------|----------\n"
        "SM   | Session Management               | 44\n"
        "AU   | Authentication                   | 28\n"
        "AZ   | Authorization                    | 10\n"
        "IV   | Input Validation & Output Enc.   | 19\n"
        "XS   | Cross-Site Scripting              | 5\n"
        "AP   | API Security                     | 6\n"
        "CR   | Cryptography & Secrets            | 7\n"
        "EL   | Error Handling & Logging          | 8\n"
        "SH   | Security Headers                  | 9\n"
        "FU   | File Upload Security              | 5\n"
        "DS   | Dependency & Supply Chain         | 3\n"
        "DP   | Data Protection & Privacy         | 6\n\n"
        "All 150 guidelines are severity: CRITICAL.\n"
        "Use search_guidelines with domain_code to filter by domain.\n"
    )


@mcp.resource("guidelines://summary")
def guidelines_summary() -> str:
    """Overview of the security guidelines framework and available tools."""
    return (
        "Security Guidelines Framework\n"
        "=============================\n\n"
        "This organization maintains 150 security development guidelines\n"
        "organized across 12 domains. Every guideline is CRITICAL severity.\n\n"
        "Guideline structure:\n"
        "- Each guideline has a unique ID (e.g., AU-01.1, SM-04.1)\n"
        "- IDs follow the pattern: DOMAIN_CODE-SECTION.SUB_ID\n"
        "- Full requirement text describes what code MUST or MUST NOT do\n"
        "- Detection hints list code patterns that signal violations\n"
        "- Language tags indicate which languages the guideline applies to\n\n"
        "Workflow:\n"
        "- scan: classify files and detect secrets in one stateless call\n"
        "- search_guidelines: semantic search over the guideline knowledge base\n"
        "- save_report: finalize the report (returned to the client to save)\n"
    )


@mcp.resource("guidelines://{domain_code}")
def domain_guidelines(domain_code: str) -> str:
    """All guidelines for a specific security domain.

    Valid domain codes: SM, AU, AZ, IV, XS, AP, CR, EL, SH, FU, DS, DP.
    """
    project_root = Path(__file__).resolve().parent.parent.parent
    chunks_path = project_root / "knowledge" / "chunks" / "guidelines_chunks.json"

    try:
        with open(chunks_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return "Error: Guidelines chunks file not found."

    code = domain_code.upper()
    domain_chunks = [c for c in data["chunks"] if c["domain_code"] == code]

    if not domain_chunks:
        valid_codes = sorted(set(c["domain_code"] for c in data["chunks"]))
        return (
            f"No guidelines found for domain code '{code}'.\n"
            f"Valid codes: {', '.join(valid_codes)}"
        )

    domain_name = domain_chunks[0]["domain"]
    lines = [f"# {domain_name} ({code}) — {len(domain_chunks)} guidelines\n"]

    current_parent = ""
    for chunk in domain_chunks:
        if chunk["parent_code"] != current_parent:
            current_parent = chunk["parent_code"]
            lines.append(f"\n## {chunk['parent_code']} — {chunk['parent_title']}\n")
        lines.append(f"### {chunk['id']} [{chunk['severity']}]")
        lines.append(chunk["text"])
        if chunk.get("detection_hints"):
            lines.append(f"Detection patterns: {', '.join(chunk['detection_hints'])}")
        if chunk.get("applies_to"):
            lines.append(f"Languages: {', '.join(chunk['applies_to'])}")
        lines.append("")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
# PROMPTS (3)
# ═══════════════════════════════════════════════════════════════════

@mcp.prompt()
def security_review(target_description: str = "the provided code") -> str:
    """Comprehensive security review workflow.

    Guides a 4-step review: scan, code analysis with guideline lookup,
    report synthesis, and finalizing the report.
    Uses all tools: scan, search_guidelines, save_report.
    """
    return f"""You are a senior application security engineer conducting a
compliance review against the organization's 150 security development
guidelines across 12 domains. All guidelines are CRITICAL severity.

TARGET: {target_description}

═══════════════════════════════════════════════
STEP 1 — SCAN
═══════════════════════════════════════════════
Forward the code you want reviewed to the scan tool as a list of
{{"path", "content"}} objects. scan returns, in one call:
- a classification manifest (type, language, applicable_domains per file)
- redacted hardcoded-secret findings (every one maps to CR-05.1)
- a "skipped" list of files that were too large to review

BATCHING: scan accepts at most ~6 MB of combined content per call. If the
codebase is larger, split the files across multiple scan calls and combine
the results — findings are independent across calls. Exclude dependency,
vendor, build, lockfile, and binary files before sending. If a call returns
{{"error": "payload_too_large"}}, split that batch and retry each half.

Record every secret finding — each hardcoded secret is a CRITICAL violation
regardless of context.

═══════════════════════════════════════════════
STEP 2 — CODE ANALYSIS
═══════════════════════════════════════════════
For each source_code and config file in the manifest, examine the content
you forwarded. Look for patterns like: weak hashing (md5/sha1 for passwords),
SQL string concatenation, missing input validation/output encoding, insecure
cookie/session config, missing authn/authz checks, unsafe deserialization,
missing security headers, debug mode in production, unpinned dependencies,
sensitive data in logs or URLs.

For each suspicious pattern, call search_guidelines with a TARGETED query,
using the file's applicable_domains as domain_code and including the language.
  GOOD: search_guidelines("SQL injection parameterized", domain_code="IV", language="python")
  BAD:  search_guidelines("security issues")

Read the full requirement text and decide whether the code actually violates
that specific requirement. Record violations with: guideline_id, file path and
line number(s), what the code does wrong, the code evidence, and remediation.

Context-aware judgment:
- hashlib.md5(password) -> CRITICAL (AU-01.1); hashlib.md5(cache_key) -> not a finding
- DEBUG=True in production -> CRITICAL (EL-01.1); in test settings -> acceptable
- Math.random() for session IDs -> CRITICAL (SM-01.1); for UI animation -> not a finding

UNGUIDELINED CRITICAL FINDINGS: If an issue is clearly exploitable and CRITICAL
but matches no guideline, report it separately with a "UG-xxx" ID, stating why
it is critical and exploitable. Do NOT use this for theoretical or low-severity
observations. The bar: would a competent attacker exploit this to compromise
the application?

═══════════════════════════════════════════════
STEP 3 — SYNTHESIS
═══════════════════════════════════════════════
Compile a compliance report:
### Executive Summary  (files reviewed, findings count, PASS/FAIL — FAIL if any CRITICAL)
### Findings by Domain  (grouped; each: **[guideline_id]** path:line — desc, Evidence, Fix)
### Secret Scan Results (table of all secret findings)
### Summary Statistics  (files scanned, violations, domains with/without violations)
### Additional Critical Findings (No Guideline Match)  (UG-xxx; omit if none)
### Top 5 Priority Remediations  (ranked, each with a guideline/UG id and action)

If you batched the scan, note any "skipped" files as NOT reviewed.

═══════════════════════════════════════════════
STEP 4 — FINALIZE REPORT
═══════════════════════════════════════════════
Call save_report with the COMPLETE report as content. It returns the report
with metadata prepended; write that returned content to a file on disk
(e.g. security_report.md). Do NOT summarize or truncate — pass the full report."""


@mcp.prompt()
def quick_file_review(file_path: str = "the file") -> str:
    """Quick security review of a single file."""
    return f"""Review {file_path} against the organization's security guidelines.

1. Forward the file to scan as [{{"path": "{file_path}", "content": "<file text>"}}].
   Note its classification and any secret findings (secrets map to CR-05.1).
2. Identify the file's language and type.
3. Based on patterns you observe in the content, call search_guidelines with
   targeted queries, using the file's applicable_domains and language as filters.
4. For each returned guideline, check whether the code actually violates it.

Report findings as:
- **[guideline_id]** line N — what violates the guideline
- Fix: specific remediation

Context matters: md5 for passwords -> CRITICAL (AU-01.1); md5 for cache key -> skip.
Map every finding to a guideline ID when possible. If you find a clearly
exploitable CRITICAL issue with no matching guideline, report it with a UG-xxx
ID and explain why. Do NOT use UG-xxx for low-severity or theoretical risks.

If no violations are found, state which domains were checked and that the file passes.

5. FINAL STEP: Call save_report with the complete review as content, then write
   the returned report to a file (e.g. security_report.md)."""


@mcp.prompt()
def secrets_audit(target_description: str = "the provided code") -> str:
    """Scan for hardcoded secrets and report findings."""
    return f"""Forward {target_description} to the scan tool.

Read the "secret_findings" array from the result and present it as a table:

| File | Line | Secret Type | Evidence |
|------|------|-------------|----------|
| ...  | ...  | ...         | ...      |

All findings violate guideline CR-05.1 (Secret Storage). For each, give a
specific remediation by type:
- API keys -> environment variables or a secret manager (Vault, AWS Secrets
  Manager, Azure Key Vault)
- Private keys -> a secure key store, never committed to VCS
- Database URLs with credentials -> environment variables, separate credentials
- Passwords -> a secrets manager, never hardcoded

If "skipped" is non-empty, note those files were not scanned (too large).
If there are no findings, confirm the scan covered the files and found no
secrets matching the 17 detection patterns."""


# ═══════════════════════════════════════════════════════════════════
# HTTP transport: auth + trailing-slash + health, ahead of the router
# ═══════════════════════════════════════════════════════════════════

async def _send_json(send, status: int, payload: dict):
    body = json.dumps(payload).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})


def _wrap_http(app):
    """ASGI middleware placed BEFORE Starlette's router.

    - serves an unauthenticated /healthz for container/orchestrator checks
    - normalizes /mcp/ -> /mcp so Starlette's 307 redirect can't drop the
      method or the Authorization header
    - enforces a bearer token (MCP_AUTH_TOKEN) on the MCP endpoint
    """
    token = os.environ.get("MCP_AUTH_TOKEN", "").strip()
    mcp_path = mcp.settings.streamable_http_path  # "/mcp"

    if not token:
        print(
            "[security-checker] WARNING: MCP_AUTH_TOKEN is not set — the HTTP "
            "endpoint is UNAUTHENTICATED. Set it before exposing on any network.",
            file=sys.stderr,
        )

    async def middleware(scope, receive, send):
        if scope["type"] != "http":
            await app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Health check (no auth, no MCP handshake)
        if path == "/healthz":
            await _send_json(send, 200, {"status": "ok"})
            return

        # This server is NOT an OAuth-protected resource. Answer OAuth discovery
        # probes (e.g. VS Code requesting /.well-known/oauth-protected-resource)
        # with 404 — WITHOUT requiring the token — so the client uses the
        # configured static bearer header instead of starting an OAuth/DCR flow.
        # Returning 401 here makes clients believe the resource is OAuth-protected
        # and triggers the "Dynamic Client Registration not supported" prompt.
        if path.startswith("/.well-known/"):
            await _send_json(send, 404, {"error": "not_found"})
            return

        # Normalize trailing slash to avoid the redirect that drops auth/method
        if path == mcp_path + "/":
            scope = dict(scope)
            scope["path"] = mcp_path
            scope["raw_path"] = mcp_path.encode()

        # Bearer auth on the MCP endpoint.
        # NOTE: we return 403 (Forbidden), not 401 (Unauthorized), on a
        # missing/invalid token. A 401 is the trigger that makes IDE MCP
        # clients (notably VS Code) launch an OAuth/Dynamic-Client-Registration
        # flow — which this server does not implement — producing a
        # "client ID" prompt. 403 says "not allowed" without inviting an OAuth
        # handshake, so a client configured with the correct static header
        # connects, and one without it is simply refused.
        if token:
            headers = dict(scope.get("headers") or [])
            authz = headers.get(b"authorization", b"").decode()
            if authz != f"Bearer {token}":
                await _send_json(send, 403, {"error": "forbidden",
                                             "message": "Missing or invalid bearer token."})
                return

        await app(scope, receive, send)

    return middleware


def _run_http():
    import uvicorn

    token = os.environ.get("MCP_AUTH_TOKEN", "").strip()
    allow_open = os.environ.get("MCP_ALLOW_UNAUTHENTICATED", "").strip().lower() in ("1", "true", "yes")

    # Fail closed: do not start an unauthenticated public endpoint by accident.
    if not token and not allow_open:
        print(
            "[security-checker] REFUSING TO START: MCP_TRANSPORT=http but MCP_AUTH_TOKEN is unset.\n"
            "  An unauthenticated endpoint is reachable by anyone who can reach this host:port\n"
            "  (the entire internet on a public service such as AWS App Runner).\n"
            "  Fix: set MCP_AUTH_TOKEN to a strong secret.\n"
            "  To run open ON PURPOSE (local testing only), set MCP_ALLOW_UNAUTHENTICATED=1.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    host = os.environ.get("MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("MCP_PORT", "8000"))
    mcp.settings.host = host
    mcp.settings.port = port

    # The MCP SDK enables DNS-rebinding protection by default and only allows
    # localhost Host headers, so a request arriving via a load balancer's
    # hostname (e.g. *.on.aws) is rejected with 421 Misdirected Request. That
    # protection targets localhost-bound servers reached from a browser; here
    # the bearer token + TLS edge are the real gate. Default: allow any Host.
    # Set MCP_ALLOWED_HOSTS=host1,host2 to lock it to specific hostnames instead.
    from mcp.server.transport_security import TransportSecuritySettings

    allowed_hosts_env = os.environ.get("MCP_ALLOWED_HOSTS", "*").strip()
    if allowed_hosts_env in ("", "*"):
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        )
        print("[security-checker] Host check disabled (any Host header accepted).", file=sys.stderr)
    else:
        hosts = [h.strip() for h in allowed_hosts_env.split(",") if h.strip()]
        expanded: list[str] = []
        for h in hosts:
            expanded.append(h)              # bare host (HTTPS on :443 sends no port)
            if not h.endswith(":*"):
                expanded.append(f"{h}:*")   # and any explicit port
        origins = [f"https://{h}" for h in hosts] + [f"http://{h}" for h in hosts]
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=expanded,
            allowed_origins=origins,
        )
        print(f"[security-checker] Allowed Hosts: {expanded}", file=sys.stderr)

    app = _wrap_http(mcp.streamable_http_app())
    print(f"[security-checker] Streamable HTTP on http://{host}:{port}{mcp.settings.streamable_http_path}", file=sys.stderr)
    uvicorn.run(app, host=host, port=port, log_level="info")


# ─── Entry Point ──────────────────────────────────────────────────

def main():
    """Entry point. Transport chosen via MCP_TRANSPORT (stdio | http)."""
    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()
    if transport in ("http", "streamable-http"):
        _run_http()
    else:
        mcp.run()  # stdio (default)


if __name__ == "__main__":
    main()