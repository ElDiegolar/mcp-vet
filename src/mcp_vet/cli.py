"""mcp-vet CLI: the framework's terminal surface.

Usage:
  mcp-vet <target> [--json] [--gate] [--no-cache] [--strict]
                   [--harness generic|claude-code|cursor|vscode|hermes|all]
"""
from __future__ import annotations

import argparse
import json
import sys

from mcp_vet import __version__
from mcp_vet.adapters import config_for, list_adapters, spec_from_verdict
from mcp_vet.engine import vet
from mcp_vet.policy import Policy
from mcp_vet.verdict import Level


def _print_findings(v: dict, indent: int) -> None:
    for f in v["findings"]:
        loc = f"  @ {f['file']}:{f['line']}" if f["file"] else "  @ -"
        print(f"{' ' * indent}[{f['severity']:>5}] ({f['scanner']}) "
              f"{f['message']}{loc}")
        if f.get("evidence"):
            print(f"{' ' * (indent + 10)}evidence: {f['evidence'][:120]}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="mcp-vet",
        description="Trust-scan gate for MCP servers: evidence-backed verdicts "
                    "before you install.",
        epilog="Targets: npm:pkg, pypi:pkg, gh:owner/repo, ./local-dir "
               "(bare names default to npm).")
    ap.add_argument("target", help="MCP server to vet")
    ap.add_argument("--json", action="store_true", help="emit VetResult JSON")
    ap.add_argument("--gate", action="store_true",
                    help="exit 1 on DO_NOT_INSTALL (CI)")
    ap.add_argument("--no-cache", action="store_true",
                    help="bypass the local verdict cache")
    ap.add_argument("--strict", action="store_true",
                    help="no policy downgrades: raw scanner findings")
    ap.add_argument("--harness", choices=list_adapters() + ["all"],
                    help="after the verdict, emit ready-to-paste config "
                         "for this harness")
    ap.add_argument("--ttl", type=int, default=None,
                    help="verdict cache TTL in seconds")
    ap.add_argument("--version", action="version",
                    version=f"mcp-vet {__version__}")
    args = ap.parse_args(argv)

    policy = Policy(strict=args.strict)
    try:
        result = vet(args.target, use_cache=not args.no_cache, policy=policy,
                     cache=None if args.ttl is None else _cache(args.ttl))
    except Exception as e:  # noqa: BLE001
        print(f"mcp-vet: error vetting '{args.target}': {e}", file=sys.stderr)
        return 2

    d = result.to_dict()
    if args.json:
        print(json.dumps(d, indent=2))
    else:
        kind = d["kind"]
        version = f" ({d['version']})" if d.get("version") else ""
        print(f"mcp-vet: {d['target']} ({kind}{version})")
        print(f"  verdict: {d['verdict']['level']}  —  {d['verdict']['summary']}"
              f"  files: {d['files_scanned']}")
        _print_findings(d["verdict"], 2)
        prov = d.get("provenance", {})
        if prov.get("source_url"):
            print(f"  source:  {prov['source_url']}")
        if prov.get("license"):
            print(f"  license: {prov['license']}")

    if args.harness and d["verdict"]["level"] != Level.BLOCK.value:
        spec = spec_from_verdict(args.target)
        harnesses = list_adapters() if args.harness == "all" else [args.harness]
        print()
        for h in harnesses:
            out = config_for(h, spec)
            print(f"  --- {h} ---")
            print(f"  file: {out['file']}")
            print(f"  config: {json.dumps(out['config'], indent=2)}")
            print(f"  {out['instructions']}")
            print()

    if args.gate and d["verdict"]["level"] == Level.BLOCK.value:
        return 1
    return 0


def _cache(ttl: int):
    from mcp_vet.cache import VerdictCache
    return VerdictCache(ttl_s=ttl)


if __name__ == "__main__":
    raise SystemExit(main())
