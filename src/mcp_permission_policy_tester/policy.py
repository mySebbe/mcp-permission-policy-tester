"""Risk checks for MCP tool descriptions and schemas."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

HIDDEN_UNICODE_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
PROMPT_INJECTION_RE = re.compile(
    r"(?i)\b(ignore previous instructions|disregard (?:all )?instructions|system prompt|developer message|"
    r"reveal hidden|exfiltrate|jailbreak)\b"
)
SHELL_RE = re.compile(r"(?i)\b(run arbitrary shell|shell commands?|execute commands?|subprocess|command execution)\b")
FILESYSTEM_RE = re.compile(r"(?i)\b(read any file|write any file|arbitrary files?|filesystem access|full disk)\b")
NETWORK_RE = re.compile(r"(?i)\b(network requests?|internet access|any url|http requests?|external requests?)\b")
ENV_SECRET_RE = re.compile(r"(?i)\b(environment variables?|env vars?|process\.env|api keys?|access tokens?|credentials?)\b")
SECRET_FIELD_NAMES = {"apikey", "api_key", "authorization", "bearer", "credential", "credentials", "password", "secret", "token"}


def _risk(code: str, severity: str, path: str, message: str, snippet: str = "") -> dict[str, str]:
    item = {"code": code, "severity": severity, "path": path, "message": message}
    if snippet:
        item["snippet"] = snippet[:160]
    return item


def _walk(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            escaped = str(key).replace("'", "\\'")
            yield from _walk(child, f"{path}['{escaped}']")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")


def scan_policy(report: Any) -> dict[str, Any]:
    """Scan a parsed MCP tool or server JSON report for policy risk signals."""
    risks: list[dict[str, str]] = []
    if not isinstance(report, (dict, list)):
        risks.append(_risk("invalid_json_shape", "high", "$", "input must be a JSON object or list"))
        return {"ok": False, "risks": risks, "summary": {"risk_count": 1}}

    for path, value in _walk(report):
        if isinstance(value, str):
            if HIDDEN_UNICODE_RE.search(value):
                risks.append(
                    _risk("hidden_unicode", "high", path, "hidden Unicode control characters are present", value)
                )
            if PROMPT_INJECTION_RE.search(value):
                risks.append(
                    _risk("prompt_injection_phrase", "high", path, "prompt-injection style phrase detected", value)
                )
            if SHELL_RE.search(value):
                risks.append(_risk("broad_shell_permission", "high", path, "broad shell permission detected", value))
            if FILESYSTEM_RE.search(value):
                risks.append(
                    _risk("broad_filesystem_permission", "high", path, "broad filesystem permission detected", value)
                )
            if NETWORK_RE.search(value):
                risks.append(_risk("broad_network_permission", "medium", path, "broad network permission detected", value))
            if ENV_SECRET_RE.search(value):
                risks.append(_risk("secret_exposure_signal", "medium", path, "secret or environment variable access mentioned", value))

        if isinstance(value, dict):
            properties = value.get("properties")
            if isinstance(properties, dict):
                keys = {str(key).lower() for key in properties}
                normalized_keys = {re.sub(r"[^a-z0-9_]+", "", key) for key in keys}
                if {"command", "cmd", "shell"} & keys:
                    risks.append(
                        _risk(
                            "broad_shell_permission",
                            "medium",
                            f"{path}.properties",
                            "schema exposes a command-like input field",
                        )
                    )
                if {"path", "filepath", "filename"} & keys and {"recursive", "root", "glob"} & keys:
                    risks.append(
                        _risk(
                            "broad_filesystem_permission",
                            "medium",
                            f"{path}.properties",
                            "schema exposes broad filesystem traversal inputs",
                        )
                    )
                if {"url", "uri", "endpoint"} & keys and {"method", "headers"} & keys:
                    risks.append(
                        _risk(
                            "broad_network_permission",
                            "medium",
                            f"{path}.properties",
                            "schema exposes broad network request inputs",
                        )
                    )
                if SECRET_FIELD_NAMES & (keys | normalized_keys):
                    risks.append(
                        _risk(
                            "secret_input_field",
                            "medium",
                            f"{path}.properties",
                            "schema exposes a secret-like input field",
                        )
                    )

    return {"ok": not risks, "risks": risks, "summary": {"risk_count": len(risks)}}


def render_result(result: dict[str, Any], output_format: str = "text") -> str:
    if output_format == "json":
        return json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output_format != "text":
        raise ValueError(f"unsupported output format: {output_format}")
    lines = ["PASS" if result.get("ok") else "FAIL"]
    for risk in result.get("risks", []):
        lines.append(f"{risk.get('severity', 'unknown').upper()} {risk.get('code')}: {risk.get('message')} at {risk.get('path')}")
    return "\n".join(lines) + "\n"
