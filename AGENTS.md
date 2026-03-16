# AI Agent Guide - cryptomator-rust

This document provides essential information for AI agents (e.g., Cursor, Copilot, OpenCode) to effectively navigate, understand, and contribute to the `cryptomator-rust` repository. Adhering to these guidelines ensures consistency and high-quality contributions.

## Project Overview

`cryptomator-rust` is a pure-Rust implementation of the Cryptomator project, focusing on vault format 7. It provides a CLI to unlock vaults and access content via embedded WebDAV or NFS servers.

## Development Commands

### Build and Run
- **Standard Build**: `cargo build`
- **Release Build**: `cargo build --release` (or `make build`)
- **Run CLI**: `cargo run -- [args]`

### Testing
- **Run All Tests**: `cargo test` (or `make test`)
- **Run Specific Test**: `cargo test -- <test_name>`
- **Run Benchmarks**: `cargo bench`

### Quality Control
- **Linting**: `cargo clippy --all-targets --workspace -- -D warnings` (or `make clippy`)
- **Formatting Check**: `cargo fmt --all -- --check`

---

## Code Style & Conventions

### 1. Formatting
- All code must adhere to the standard `rustfmt` style.
- Run `cargo fmt` before committing changes.

### 2. Imports Organization
Group imports in the following order, separated by a single newline:
1. `std` library imports (e.g., `std::path::PathBuf`)
2. External crates (e.g., `tracing::info`, `thiserror::Error`)
3. Internal crate modules (e.g., `crate::crypto::vault`)

Example:
```rust
use std::sync::Arc;

use tracing::error;
use zeroize::Zeroizing;

use crate::crypto::error::CryptoError;
```

### 3. Naming Conventions
- **Structs/Enums/Traits**: `CamelCase` (e.g., `VaultSession`)
- **Fields/Variables/Functions**: `snake_case` (e.g., `master_key`, `derive_keys()`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `CHUNK_SIZE`)
- **Files**: `snake_case.rs`

### 4. Types and Shared State
- Use descriptive names for types.
- **Shared State**: Use `Arc<Mutex<T>>` or `Arc<RwLock<T>>` for thread-safe shared state.
- **Sensitive Data**: Always wrap sensitive keys or passwords in `zeroize::Zeroizing<T>` to ensure they are wiped from memory when dropped.

### 5. Documentation
- Use `///` for public APIs, structs, and methods.
- Include a brief summary of the item's purpose.
- Use `//` for internal implementation details.

---

## Technical Standards

### 1. Error Handling
- Use the `thiserror` crate to define custom error types.
- Prefer specific error enums like `FileSystemError` or `CryptoError`.
- **Avoid** `unwrap()` and `expect()` in library code. Propagate errors using the `?` operator.
- Provide context for errors where appropriate.

Example:
```rust
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Failed to derive master key: {0}")]
    DerivationFailed(String),
    // ...
}
```

### 2. Security
- **Memory Safety**: Avoid raw pointers unless absolutely necessary for FFI. Prefer safe Rust.
- **Zeroization**: Use `Zeroizing` for anything that might contain cryptographic material.
- **Cryptographic Operations**: Ensure all crypto logic resides in `src/crypto/`.

### 3. Logging
- Use the `tracing` crate for all logging.
- Prefer structured logging: `info!(key = %value, "Message")`.
- Available levels: `error!`, `warn!`, `info!`, `debug!`, `trace!`.

### 4. Testing Guidelines
- Write unit tests in the same file using a `mod tests` block.
- Place integration tests in the `tests/` directory.
- Use `proptest` or similar if complex input validation is needed (verify existing usage).

---

## Architecture Context

- `src/main.rs`: Entry point for the CLI, handles command-line arguments and high-level orchestration.
- `src/lib.rs`: Library interface, exports core functionality for external use.
- `src/crypto/`: Core cryptographic primitives.
  - `masterkey.rs`: Masterkey decryption and key derivation.
  - `cryptor.rs`: Encryption/decryption logic for file content and filenames.
  - `vault.rs`: Vault configuration and metadata handling.
- `src/cryptofs/`: Virtual filesystem logic.
  - `filesystem.rs`: High-level filesystem operations (read, write, list).
  - `path_obfuscation.rs`: Cryptomator's path obfuscation algorithm.
- `src/frontends/`: Network protocol implementations.
  - `webdav.rs`: WebDAV server implementation using `warp` or similar.
  - `nfs.rs`: NFSv3 server implementation.
- `src/providers/`: Backend storage abstractions.
  - `local_fs.rs`: Local filesystem backend.
  - `mem_fs.rs`: In-memory filesystem for testing.

## Contributing Workflow for Agents

When tasked with a change, follow these steps:

1.  **Analysis**: Search the codebase for relevant patterns using `grep` or `rg`.
2.  **Context**: Read the surrounding files to understand the architectural layer (e.g., `crypto` vs `frontends`).
3.  **Dependency Check**: Look at `Cargo.toml` to see if existing crates can be used instead of adding new ones.
4.  **Implementation**:
    - Follow the naming and grouping conventions strictly.
    - Use `Zeroizing` for sensitive data.
    - Implement `thiserror` based error types.
5.  **Verification**:
    - Run `cargo fmt` to ensure style consistency.
    - Run `make clippy` to catch common mistakes.
    - Run `make test` to ensure no regressions.
6.  **Documentation**: Add `///` comments for any new public-facing functions or structs.

---

## Agent-Specific Notes

- **Cursor/Copilot Rules**: No project-specific `.cursorrules` or Copilot configuration files were found in the root directory. Rely on this `AGENTS.md` and the existing codebase patterns.
- **Modification Workflow**:
  1. Read relevant files to understand local context.
  2. Check `Cargo.toml` for available dependencies before suggesting new ones.
  3. Run `make clippy` and `make test` after any modifications.
  4. Ensure any new public API is documented with `///`.
- **Refactoring**: When refactoring, ensure that error handling remains robust and follows the `thiserror` pattern used throughout the project.

---
*Generated for AI Agents working on cryptomator-rust.*
