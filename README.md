# mcp-permission-policy-tester

`mcp-permission-policy-tester` scans MCP tool descriptions and schema JSON for policy risk signals.

## 0.1.2 Highlights

- CI gates can now choose a blocking severity with `--fail-on low|medium|high`.
- Reports still list all risks while the exit code only fails at the configured threshold.
- Inputs are bounded to 1 MiB by default, with structural limits of 10,000 tools and JSON depth 100.

## Checks

- hidden Unicode control characters
- prompt-injection phrases
- broad shell permissions
- broad filesystem permissions
- broad network permissions

## Install

```bash
python -m pip install .
```

## CLI

```bash
mcp-permission-policy-tester tools.json
cat tools.json | mcp-permission-policy-tester --format json
cat tools.json | mcp-permission-policy-tester --format json --fail-on high
cat tools.json | mcp-permission-policy-tester --format json --max-input-bytes 65536
python -m mcp_permission_policy_tester --format text < tools.json
```

`--max-input-bytes` applies to both a JSON file and stdin and counts UTF-8 encoded bytes. The default is
`1048576` bytes (1 MiB). Parsed reports are also rejected when their `tools` list (or top-level tool array)
has more than 10,000 items or when JSON nesting exceeds 100 levels.

Exit codes:

- `0`: no risks detected
- `1`: one or more risks meet or exceed the configured `--fail-on` severity
- `2`: invalid input, unreadable file, invalid JSON, or an input/structure limit is exceeded

## Development

```bash
python -m unittest discover -s tests
```
