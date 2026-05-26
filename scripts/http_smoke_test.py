"""HTTP smoke test for the Security Checker MCP server.

Drives the running server with a real MCP client: lists tools, runs `scan`
on the bundled vulnerable fixtures, and exercises the batch-overflow path.

Usage:
    # against a local container
    MCP_URL=http://localhost:8000/mcp MCP_AUTH_TOKEN=local-poc-token \
        python scripts/http_smoke_test.py

    # against a deployed App Runner URL
    MCP_URL=https://xxxx.awsapprunner.com/mcp MCP_AUTH_TOKEN=... \
        python scripts/http_smoke_test.py
"""

import asyncio
import json
import os
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = os.environ.get("MCP_URL", "http://localhost:8000/mcp")
TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")
FIX = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


async def main():
    headers = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}
    async with streamablehttp_client(URL, headers=headers) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()

            tools = await s.list_tools()
            print("tools   :", sorted(t.name for t in tools.tools))
            prompts = await s.list_prompts()
            print("prompts :", sorted(p.name for p in prompts.prompts))

            # 1) scan the vulnerable fixtures
            files = [
                {"path": p.name, "content": p.read_text(errors="ignore")}
                for p in sorted(FIX.iterdir()) if p.is_file()
            ]
            res = await s.call_tool("scan", {"files": files})
            d = json.loads(res.content[0].text)
            print(f"scan    : {d['total']} files classified, "
                  f"{d['total_secret_findings']} secrets in {d['files_with_secrets']} files, "
                  f"{len(d['skipped'])} skipped")

            # 2) batch-overflow self-correction
            big = [{"path": f"f{i}.py", "content": "a" * 70000} for i in range(100)]  # ~7 MB
            res = await s.call_tool("scan", {"files": big})
            d = json.loads(res.content[0].text)
            assert d.get("error") == "payload_too_large", "expected payload_too_large"
            print(f"overflow: correctly rejected {d['received']} (limit {d['limit']})")

            print("\nSMOKE TEST PASSED")


if __name__ == "__main__":
    asyncio.run(main())
