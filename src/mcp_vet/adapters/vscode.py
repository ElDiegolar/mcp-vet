"""VS Code adapter: .vscode/mcp.json with the VS Code servers schema."""
from __future__ import annotations

from mcp_vet.adapters.base import HarnessAdapter, ServerSpec


class VSCodeAdapter(HarnessAdapter):
    name = "vscode"
    file_hint = ".vscode/mcp.json (workspace)"

    def config(self, spec: ServerSpec) -> dict:
        entry: dict = {"type": "stdio", "command": spec.command,
                       "args": list(spec.args)}
        if spec.env:
            entry["env"] = dict(spec.env)
        return {"servers": {spec.name: entry}}

    def instructions(self, spec: ServerSpec) -> str:
        return (
            "Paste into .vscode/mcp.json, then run 'Developer: Reload Window' "
            "from the command palette. (VS Code MCP config uses the "
            "\"servers\" schema, not mcpServers.)"
        )
