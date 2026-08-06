"""mcp-vet CLI: mcp-vet <target> [--json] [--gate] [--no-cache] [--ttl N]"""
from __future__ import annotations

import argparse
import json
import sys

from mcp_vet.engine import vet
from mcp_vet.verdict import Level


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="mcp-vet",
        description="Trust-scan gate for MCP servers: evidence-backed verdicts "
        "before you install. Targets: npm:pkg, pypi:pkg, gh:owner/repo, ./local-dir "
        "(bare names default to npm).",
    )
    ap.add_argument("target", help="npm:pkg | pypi:pkg | gh:owner/repo | ./path")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--gate", action="store_true",
                    help="exit 1 on DO_NOT_INSTALL (CI/automation)")
    ap.add_argument("--no-cache", action="store_true", help="bypass the verdict cache")
    ap.add_argument("--ttl", type=int, default=24 * 3600, help="cache TTL seconds")
    args = ap.parse_args(argv)

    try:
        result = vet(args.target, use_cache=not args.no_cache, ttl_s=args.ttl)
    except Exception as e:  # noqa: BLE001
        print(f"mcp-vet: error vetting '{args.target}': {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        v = result["verdict"]
        print(f"mcp-vet: {result['target']} ({result['kind']} {result['version']})")
        print(f"  verdict: {v['level']}  —  {v['summary']}")
        if result.get("license"):
            print(f"  license: {result['license']}   files: {result.get('files_scanned')}")
        if result.get("source_url"):
            print(f"  source:  {result['source_url']}")
        for f in v["findings"]:
            loc = f"{f['file']}:{f['line']}" if f.get("file") else "-"
            print(f"  [{f['severity']:>6}] ({f['scanner']}) {f['message']}  @ {loc}")
            if f.get("evidence"):
                print(f"           evidence: {f['evidence']}")

    if args.gate and result["verdict"]["level"] == Level.BLOCK.value:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
