"""Claude Code adapter: `claude mcp add` or ~/.claude.json mcpServers."""
from __future__ import annotations

from mcp_vet.adapters.base import HarnessAdapter, ServerSpec


class ClaudeCodeAdapter(HarnessAdapter):
    name = "claude-code"
    file_hint = "~/.claude.json (mcpServers) or `claude mcp add`"

    def config(self, spec: ServerSpec) -> dict:
        return {"mcpServers": {spec.name: spec.mcp_entry()}}

    def install_command(self, spec: ServerSpec) -> str:
        parts = [spec.command] + list(spec.args)
        return f"claude mcp add {spec.name} -- {' '.join(parts)}"

    def instructions(self, spec: ServerSpec) -> str:
        return (
            f"Easiest: {self.install_command(spec)}\n"
            f"(or paste the mcpServers block into ~/.claude.json, then restart Claude Code)"
        )
