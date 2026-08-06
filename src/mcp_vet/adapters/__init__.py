"""Adapter registry: get_adapter / list_adapters / config_for."""
from __future__ import annotations

from mcp_vet.adapters.base import HarnessAdapter, ServerSpec
from mcp_vet.adapters.claude_code import ClaudeCodeAdapter
from mcp_vet.adapters.cursor import CursorAdapter
from mcp_vet.adapters.generic import GenericAdapter
from mcp_vet.adapters.hermes import HermesAdapter
from mcp_vet.adapters.vscode import VSCodeAdapter

_ADAPTERS: dict[str, HarnessAdapter] = {}
for _a in (GenericAdapter, ClaudeCodeAdapter, CursorAdapter,
           VSCodeAdapter, HermesAdapter):
    _ADAPTERS[_a.name] = _a()


def register(adapter: HarnessAdapter) -> None:
    _ADAPTERS[adapter.name] = adapter


def list_adapters() -> list[str]:
    return sorted(_ADAPTERS)


def get_adapter(name: str) -> HarnessAdapter:
    if name not in _ADAPTERS:
        raise KeyError(f"unknown harness '{name}' — available: {list_adapters()}")
    return _ADAPTERS[name]


def config_for(harness: str, spec: ServerSpec) -> dict:
    """Framework-standard adapter output for any registered harness."""
    return get_adapter(harness).emit(spec)


def spec_from_verdict(target: str, command: str = "uvx",
                      args: list[str] | None = None,
                      env: dict[str, str] | None = None) -> ServerSpec:
    """Build a ServerSpec for installing a vetted server via this framework."""
    args = list(args or [])
    if not args:
        args = [target]
    return ServerSpec(name=target.split("/")[-1].replace("@", "").replace(":", "-"),
                      command=command, args=args, env=env)
