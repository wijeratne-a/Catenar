# Contributing to Catenar

Thank you for your interest in contributing to Catenar. This document explains how to report bugs, request features, and submit pull requests.

## Code of Conduct

By participating, you are expected to uphold a respectful and inclusive environment. Report unacceptable behavior to the maintainers.

## How to Contribute

### Reporting Bugs

- Use the [GitHub Issues](https://github.com/wijeratne-a/Catenar/issues) tracker
- Include Catenar version (from `VERSION` file), OS, and steps to reproduce
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

### Requesting Features

- Open an issue with the `enhancement` label
- Describe the use case and proposed solution
- Enterprise features may be discussed separately

### Pull Requests

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name main
   ```

2. **Make your changes** following our code style (see below)

3. **Ensure tests pass**:
   ```bash
   make test
   ```

4. **Commit** with clear messages:
   ```
   feat(proxy): add X
   fix(verifier): correct Y
   docs: update Z
   ```

5. **Push** and open a PR against `main`

6. **Address review feedback** promptly

## Git Branch Strategy

- **main**: Production-ready community edition (stable). All PRs merge here.
- **staging**: Pre-release testing before tagging.
- **feature/\***: Feature branches; branch from `main`, merge back to `main`.
- **release/\***: Hotfix branches for patch releases.

**Releases**: Community editions are tagged from `main` (e.g., `v0.1.0`). Use [Semantic Versioning](https://semver.org/).

## Code Style

- **Rust** (`core/proxy`, `core/verifier`, `core/crypto`): `cargo fmt`, `cargo clippy`
- **Python** (`sdks/python`): Black, type hints where practical
- **TypeScript/React** (`dashboard`, `sdks/nodejs`): ESLint, Prettier (if configured)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
