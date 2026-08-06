"""Harness adapters: emit ready-to-paste config for any agent-IDE harness.

The universal MCP server descriptor (ServerSpec) is rendered into each
harness's own config schema, so the framework's answer to "how do I wire
this in?" is always: pick your harness, paste the block.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ServerSpec:
    """The harness-independent description of an MCP server to install."""
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None

    def mcp_entry(self) -> dict:
        """The universal mcpServers entry (MCP standard block)."""
        e: dict = {"command": self.command, "args": list(self.args)}
        if self.env:
            e["env"] = dict(self.env)
        return e

    def display(self) -> str:
        env = " ".join(f"{k}={v}" for k, v in (self.env or {}).items())
        parts = [env, self.command] + list(self.args)
        return " ".join(p for p in parts if p)


class HarnessAdapter:
    name: str = ""
    file_hint: str = ""

    def config(self, spec: ServerSpec) -> dict:
        raise NotImplementedError

    def instructions(self, spec: ServerSpec) -> str:
        raise NotImplementedError

    def emit(self, spec: ServerSpec) -> dict:
        """Framework-standard adapter output: config + where it goes + how."""
        return {
            "harness": self.name,
            "config": self.config(spec),
            "file": self.file_hint,
            "instructions": self.instructions(spec),
        }
