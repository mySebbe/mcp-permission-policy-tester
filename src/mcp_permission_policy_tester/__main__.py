"""CLI entry point for mcp-permission-policy-tester."""

from __future__ import annotations

import argparse
import json
import sys

from ._version import __version__
from .policy import (
    MAX_JSON_DEPTH,
    ReportLimitError,
    apply_severity_threshold,
    render_result,
    scan_policy,
    validate_report_limits,
)

DEFAULT_MAX_INPUT_BYTES = 1_048_576
READ_CHUNK_SIZE = 64 * 1024
MAX_INPUT_BYTES_ERROR = "input exceeds --max-input-bytes limit of {limit} bytes"


class InputLimitError(ValueError):
    """Raised when an input stream exceeds the configured byte limit."""


def _read_limited(stream: object, max_input_bytes: int) -> str:
    chunks: list[bytes] = []
    total_bytes = 0
    while total_bytes <= max_input_bytes:
        remaining = max_input_bytes - total_bytes
        read_size = min(READ_CHUNK_SIZE, remaining + 1)
        chunk = stream.read(read_size)  # type: ignore[attr-defined]
        if not chunk:
            break
        if isinstance(chunk, str):
            encoded_chunk = chunk.encode("utf-8")
        else:
            encoded_chunk = bytes(chunk)
        total_bytes += len(encoded_chunk)
        if total_bytes > max_input_bytes:
            raise InputLimitError(MAX_INPUT_BYTES_ERROR.format(limit=max_input_bytes))
        chunks.append(encoded_chunk)
    return b"".join(chunks).decode("utf-8")


def _read(path: str | None, max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES) -> str:
    if not path or path == "-":
        stream = getattr(sys.stdin, "buffer", sys.stdin)
        return _read_limited(stream, max_input_bytes)
    with open(path, "rb") as handle:
        return _read_limited(handle, max_input_bytes)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


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
    parser.add_argument(
        "--max-input-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_INPUT_BYTES,
        help=f"Maximum UTF-8 input size for files and stdin (default: {DEFAULT_MAX_INPUT_BYTES}).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = json.loads(_read(args.path, args.max_input_bytes))
        validate_report_limits(report)
    except InputLimitError as exc:
        print(f"mcp-permission-policy-tester: {exc}", file=sys.stderr)
        return 2
    except ReportLimitError as exc:
        print(f"mcp-permission-policy-tester: invalid input: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"mcp-permission-policy-tester: {exc}", file=sys.stderr)
        return 2
    except UnicodeDecodeError as exc:
        print(f"mcp-permission-policy-tester: invalid UTF-8: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"mcp-permission-policy-tester: invalid JSON: {exc}", file=sys.stderr)
        return 2
    except RecursionError:
        print(
            "mcp-permission-policy-tester: invalid input: "
            f"JSON nesting depth exceeds maximum of {MAX_JSON_DEPTH}",
            file=sys.stderr,
        )
        return 2

    result = apply_severity_threshold(scan_policy(report), args.fail_on)
    sys.stdout.write(render_result(result, args.format))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
