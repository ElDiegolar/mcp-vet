"""Generic adapter: the universal mcpServers block, works anywhere that
speaks standard MCP config (most harnesses)."""
from __future__ import annotations

from mcp_vet.adapters.base import HarnessAdapter, ServerSpec


class GenericAdapter(HarnessAdapter):
    name = "generic"
    file_hint = "any mcpServers block (e.g. your harness's MCP config file)"

    def config(self, spec: ServerSpec) -> dict:
        return {"mcpServers": {spec.name: spec.mcp_entry()}}

    def instructions(self, spec: ServerSpec) -> str:
        return (
            f"Paste into your harness's mcpServers configuration.\n"
            f"Run: {spec.display()}"
        )
