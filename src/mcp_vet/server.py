"""MCP server surface: vet MCP servers from inside your agent-IDE harness."""
from __future__ import annotations

from mcp_vet.engine import scan_local_dir, vet
from mcp_vet.verdict import Verdict
from fastmcp import FastMCP

mcp = FastMCP("mcp-vet")


@mcp.tool()
def vet_server(target: str) -> dict:
    """Vet an MCP server before installing it. Target forms: npm:pkg,
    pypi:pkg, gh:owner/repo, or ./local-dir (bare names default to npm).
    Returns an evidence-backed verdict: SAFE_TO_INSTALL /
    REVIEW_BEFORE_INSTALL / DO_NOT_INSTALL with findings."""
    return vet(target)


@mcp.tool()
def vet_directory(path: str) -> dict:
    """Scan a local directory of source code and return a verdict."""
    findings, nfiles = scan_local_dir(path)
    verdict = Verdict.from_findings(findings)
    return {"path": path, "files_scanned": nfiles, "verdict": verdict.to_dict()}


@mcp.tool()
def get_verdict(target: str) -> dict:
    """Return the cached verdict for a target (scans if not cached)."""
    return vet(target, use_cache=True)


@mcp.tool()
def list_scanners() -> list[str]:
    """List the static checks mcp-vet runs: ssrf, exec, secrets, auth,
    provenance, deps."""
    return ["ssrf", "exec", "secrets", "auth", "provenance", "deps"]


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
