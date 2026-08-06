"""Hermes Agent adapter: ~/.hermes/config.yaml under the mcp_servers key.

Hermes filters the subprocess env (only explicitly-listed vars pass) and
registers tools as mcp_<server>_<tool>. See the hermes-agent skill's
native-mcp reference for the canonical format.
"""
from __future__ import annotations

from mcp_vet.adapters.base import HarnessAdapter, ServerSpec


class HermesAdapter(HarnessAdapter):
    name = "hermes"
    file_hint = "~/.hermes/config.yaml under `mcp_servers`"

    def config(self, spec: ServerSpec) -> dict:
        entry: dict = {"command": spec.command, "args": list(spec.args)}
        if spec.env:
            entry["env"] = dict(spec.env)
        return {"mcp_servers": {spec.name: entry}}

    def instructions(self, spec: ServerSpec) -> str:
        return (
            "Add the block under `mcp_servers` in ~/.hermes/config.yaml "
            "(use `hermes config set` or edit carefully — never break YAML "
            "indentation), then restart Hermes. Tools appear as "
            f"mcp_{spec.name.replace('-', '_')}_*. Note: Hermes only passes "
            "env vars you explicitly list here — API keys are NOT inherited."
        )
