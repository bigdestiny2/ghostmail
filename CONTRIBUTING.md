# Contributing to GhostMail

Thanks for your interest in contributing.

## Getting Started

```bash
git clone https://github.com/ghostmail/ghostmail.git
cd ghostmail
make build
make test
```

## Development

- Go 1.24+
- No external database — SQLite is embedded
- `make build` compiles both `ghostmail` and `ghostctl`
- `make test` runs all tests with the race detector

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Write tests for new functionality
3. Run `go vet ./...` and `make test` before submitting
4. Keep PRs focused — one feature or fix per PR
5. Update the example config if you add new config options

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Error messages start lowercase, no trailing punctuation
- Use `slog` for structured logging
- No `panic()` in library code

## Crypto Changes

Changes to `internal/crypto/` require extra scrutiny:

- Never store plaintext keys on disk
- Always call `crypto.Wipe()` on sensitive material when done
- Add tests that verify encryption round-trips
- Document the cryptographic rationale in code comments

## Reporting Bugs

Open a GitHub issue with:
- GhostMail version (`ghostctl version`)
- OS and architecture
- Steps to reproduce
- Expected vs actual behavior

## Security Issues

Do NOT open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
