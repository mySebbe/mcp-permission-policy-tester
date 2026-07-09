# Security Review 2026-07

## Scope

Review date: 2026-07-09

This review covers the local CLI input boundary in `mcp-permission-policy-tester`, specifically file and
stdin reads, JSON parsing, parsed tool-list limits, and regression coverage. The repository has no server,
network, or runtime dependency surface in `pyproject.toml`.

## Evidence

- `src/mcp_permission_policy_tester/__main__.py:28-53` reads in bounded chunks, stops as soon as the
  configured UTF-8 byte limit is exceeded, uses the same helper for files and stdin, and parses only after
  the limit check.
- `src/mcp_permission_policy_tester/__main__.py:74-110` exposes `--max-input-bytes`, reports oversized input
  and structural failures on stderr, and returns exit code 2 for those input errors. Parser recursion errors
  are converted to the configured depth-limit message.
- `src/mcp_permission_policy_tester/policy.py:21-76` defines the 10,000-item and depth-100 defaults and
  validates them without recursive Python traversal.
- `tests/test_policy.py:121-193` covers oversized stdin, oversized files, oversized tool lists, and JSON
  nesting beyond the structural limit using subprocess-level exit-code assertions.

## Findings

### Resolved: unbounded input reads

The CLI now uses `_read_limited` for both input sources. It requests bounded chunks and stops as soon as the
configured byte limit is exceeded, returning a clear exit-2 error that includes the configured limit.

### Resolved: parser resource amplification

The parsed top-level tool list, or a top-level list of tools, is capped at 10,000 items. The complete parsed
JSON value is capped at depth 100. The depth walk is iterative, and a `RecursionError` from the JSON parser
is also converted into an exit-2 input error.

### Residual limitation: heuristic detection

The scanner remains heuristic. A successful scan is not proof that an MCP tool is safe; this is consistent
with the repository's existing `SECURITY.md` scope statement. The new bounds reduce input and traversal
resource exposure but do not replace policy review.

## Verification

Executed from the repository root on 2026-07-09:

| Check | Result |
| --- | --- |
| `python -m unittest discover -s tests` | Exit 0; 11 tests passed |
| `python -m ruff check .` | Exit 0; all checks passed |
| `python -m bandit -r src -q` | Exit 0; no findings reported |
| `python -m pip_audit` | Exit 0; no known vulnerabilities found; `smolagents 1.27.0.dev0` was skipped because it is not available on PyPI |
| `python -m build --sdist --wheel` | Exit 0; built `mcp_permission_policy_tester-0.1.2.tar.gz` and `mcp_permission_policy_tester-0.1.2-py3-none-any.whl` |

The scope is local and bounded by the explicit limits above. No high-severity issue remains open in the
input-handling change based on the code evidence and checks listed here.
