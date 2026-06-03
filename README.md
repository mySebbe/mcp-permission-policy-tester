# mcp-permission-policy-tester

`mcp-permission-policy-tester` scans MCP tool descriptions and schema JSON for policy risk signals.

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
python -m mcp_permission_policy_tester --format text < tools.json
```

Exit codes:

- `0`: no risks detected
- `1`: one or more risks detected
- `2`: invalid input, unreadable file, or invalid JSON

## Development

```bash
python -m unittest discover -s tests
```
