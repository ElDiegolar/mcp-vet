"""MCP server surface: vet MCP servers from inside any agent-IDE harness.

Tools: vet_server, vet_directory, get_verdict, list_scanners,
       list_harnesses, get_config — all thin over the framework core.
"""
from __future__ import annotations

from mcp_vet.adapters import config_for, list_adapters, spec_from_verdict
from mcp_vet.engine import scan_local_dir, vet
from mcp_vet.policy import Policy
from mcp_vet.scan import auth, deps, exec as exec_scan, secrets, ssrf
from fastmcp import FastMCP

mcp = FastMCP("mcp-vet")

SCANNERS = {"ssrf": ssrf, "exec": exec_scan, "secrets": secrets,
            "auth": auth, "deps": deps}


@mcp.tool()
def vet_server(target: str, strict: bool = False) -> dict:
    """Vet a remote MCP server (npm:pkg, pypi:pkg, gh:owner/repo, or bare
    npm name). Returns the VetResult dict: verdict level/summary/findings,
    provenance, files scanned."""
    return vet(target, policy=Policy(strict=strict)).to_dict()


@mcp.tool()
def vet_directory(path: str, strict: bool = False) -> dict:
    """Vet a local MCP server source directory (offline). Returns the
    VetResult dict."""
    findings, count = scan_local_dir(path)
    from mcp_vet.verdict import Verdict
    return {"target": path, "kind": "local", "version": None,
            "verdict": Verdict.from_findings(findings).to_dict(),
            "provenance": {"source": "local directory"},
            "files_scanned": count, "duration_s": 0.0}


@mcp.tool()
def get_verdict(target: str) -> dict:
    """Return the cached verdict for a target if fresh, else vet it now."""
    return vet(target).to_dict()


@mcp.tool()
def list_scanners() -> list[str]:
    """The static scanners this framework runs."""
    return sorted(SCANNERS)


@mcp.tool()
def list_harnesses() -> list[str]:
    """Harnesses with ready-to-paste config adapters."""
    return list_adapters()


@mcp.tool()
def get_config(harness: str, name: str, command: str = "uvx",
               args: list[str] | None = None,
               env: dict[str, str] | None = None) -> dict:
    """Emit the ready-to-paste MCP config block for a harness
    (generic|claude-code|cursor|vscode|hermes)."""
    spec = spec_from_verdict(name, command=command, args=args, env=env)
    return config_for(harness, spec)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
