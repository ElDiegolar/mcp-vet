"""Cursor adapter: .cursor/mcp.json (project) or ~/.cursor/mcp.json (global)."""
from __future__ import annotations

from mcp_vet.adapters.base import HarnessAdapter, ServerSpec


class CursorAdapter(HarnessAdapter):
    name = "cursor"
    file_hint = ".cursor/mcp.json (project) or ~/.cursor/mcp.json (global)"

    def config(self, spec: ServerSpec) -> dict:
        return {"mcpServers": {spec.name: spec.mcp_entry()}}

    def instructions(self, spec: ServerSpec) -> str:
        return (
            "Paste into .cursor/mcp.json (project) or ~/.cursor/mcp.json "
            "(global), then reload the Cursor window (Cmd/Ctrl+Shift+P -> "
            "'Reload Window')."
        )
