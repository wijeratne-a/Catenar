# Contributing to Aegis Enterprise

## Submodule Workflow

Aegis Enterprise includes `aegis-core` as a git submodule. To pull the latest core changes:

```bash
git submodule update --remote core
```

After updating the submodule, run `cargo build` and `cargo test` to ensure compatibility.
