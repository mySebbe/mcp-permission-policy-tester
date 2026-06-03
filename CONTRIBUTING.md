# Contributing

## Local Setup

```bash
python -m pip install -e .
python -m unittest discover -s tests
```

## Guidelines

- Keep risk checks explainable and deterministic.
- Add tests for new phrases or schema heuristics.
- Avoid network calls in tests.
- Prefer stdlib APIs over dependencies.

Release instructions live in [PUBLISHING.md](PUBLISHING.md).
