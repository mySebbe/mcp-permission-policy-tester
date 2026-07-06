"""CLI entry point for mcp-permission-policy-tester."""

from __future__ import annotations

import argparse
import json
import sys

from ._version import __version__
from .policy import apply_severity_threshold, render_result, scan_policy


def _read(path: str | None) -> str:
    if not path or path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan MCP tool descriptions and schemas for policy risks.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("path", nargs="?", help="JSON file to scan. Reads stdin when omitted or '-'.")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high"),
        default="medium",
        help="Return exit code 1 only when a risk has this severity or higher.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = json.loads(_read(args.path))
    except OSError as exc:
        print(f"mcp-permission-policy-tester: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"mcp-permission-policy-tester: invalid JSON: {exc}", file=sys.stderr)
        return 2

    result = apply_severity_threshold(scan_policy(report), args.fail_on)
    sys.stdout.write(render_result(result, args.format))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
