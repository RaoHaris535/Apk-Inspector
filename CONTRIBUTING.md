# Contributing to APKInspector

## Development workflow

1. Create a focused branch from `main`.
2. Keep changes small and explain the motivation in the commit message.
3. Run frontend linting and tests plus backend linting and tests.
4. Open a pull request with screenshots for interface changes.

## Commit style

Use conventional commit prefixes such as `feat`, `fix`, `test`, `docs`,
`refactor`, and `chore`.

## Safety requirements

- Never execute an uploaded APK.
- Treat filenames and archive paths as untrusted input.
- Keep extraction bounded by file count and uncompressed size.
- Do not commit APK samples, credentials, reports, or user uploads.
