# Changelog

All notable changes to `mcp-permission-policy-tester` will be documented in this file.

The format is based on Keep a Changelog, and this project uses semantic versioning.

## [Unreleased]

- Added bounded file and stdin reads with a 1 MiB default `--max-input-bytes` limit.
- Added exit code 2 errors for oversized input and conservative limits of 10,000 tools and JSON depth 100.

## [0.1.2] - 2026-07-06

- Updated GitHub Actions workflow dependencies to current major versions.
- Modernized package license metadata to avoid current Setuptools deprecation warnings.
- Added `--fail-on` severity gating for CI workflows.
- Added blocking-risk counts to JSON summaries while continuing to render all detected risks.

## [0.1.1] - 2026-06-17

- Added secret-like schema field detection.
- Added environment-variable and credential exposure phrase detection.
- Fixed GitHub Actions workflow pins to supported action versions.

## [0.1.0] - 2026-06-03

- Initial open-source release with CLI, examples, tests, GitHub workflows, security policy, and contributor docs.
