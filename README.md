# better-auth-rs

**Rust implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth) - a multi-repository, multi-language authentication protocol.

This is a full Rust port of the TypeScript reference implementation with both client and server components.

## What's Included

- ✅ **Client + Server** - Full protocol implementation
- ✅ **Type-Safe** - Leverages Rust's powerful type system
- ✅ **Zero-Cost Abstractions** - High performance with trait-based design
- ✅ **Async with Tokio** - Built with async/await throughout
- ✅ **Complete Test Suite** - Unit and integration tests
- ✅ **Example Server** - HTTP server for integration testing

## Quick Start

This repository is a submodule of the [main spec repository](https://github.com/jasoncolburne/better-auth). For the full multi-language setup, see the parent repository.

### Setup

```bash
make setup          # cargo fetch
```

### Running Tests

```bash
make test           # Run cargo test
make type-check     # Run cargo check
make lint           # Run cargo clippy
make format-check   # Check code formatting
```

### Running Example Server

```bash
make server         # Start HTTP server on localhost:8080
```

## Development

This implementation uses:
- **Rust 2021 edition** for modern Rust features
- **Cargo** for dependency management
- **Tokio** for async runtime
- **serde** for JSON serialization
- **Trait-based architecture** for flexibility

All development commands use standardized `make` targets:

```bash
make setup          # cargo fetch
make test           # cargo test
make type-check     # cargo check
make lint           # cargo clippy
make format         # cargo fmt
make format-check   # cargo fmt --check
make build          # cargo build --release
make clean          # cargo clean
make server         # Run example server
```

## Architecture

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation including:
- Directory structure and key components
- Rust-specific patterns (traits, ownership, error handling)
- Message types and trait definitions
- Usage examples and API patterns

### Key Features

- **Trait-Based Architecture**: Hasher, Noncer, Verifier, SigningKey, VerificationKey traits
- **Type Safety and Ownership**: Leverages Rust's ownership system
- **Error Handling**: `Result<T, E>` with custom error types
- **Serde for Serialization**: All messages derive `Serialize` and `Deserialize`
- **Async with Tokio**: All I/O operations are async

### Reference Implementations

The `tests/implementation/` directory contains reference implementations using:
- **blake3** for cryptographic hashing
- **p256** for ECDSA P-256 signing/verification
- **rand** for secure random generation
- **chrono** for timestamps
- **serde_json** for JSON serialization

## Integration with Other Implementations

This Rust implementation can be used:
- As a **client** for testing against TypeScript, Python, Rust, Go, or Ruby servers
- As a **server** for testing TypeScript, Python, Rust, Swift, Dart, or Kotlin clients

See `examples/server.rs` for the HTTP server implementation.

## Related Implementations

**Full Implementations (Client + Server):**
- [TypeScript](https://github.com/jasoncolburne/better-auth-ts) - Reference implementation
- [Python](https://github.com/jasoncolburne/better-auth-py)
- [Rust](https://github.com/jasoncolburne/better-auth-rs) - **This repository**

**Server-Only:**
- [Go](https://github.com/jasoncolburne/better-auth-go)
- [Ruby](https://github.com/jasoncolburne/better-auth-rb)

**Client-Only:**
- [Swift](https://github.com/jasoncolburne/better-auth-swift)
- [Dart](https://github.com/jasoncolburne/better-auth-dart)
- [Kotlin](https://github.com/jasoncolburne/better-auth-kt)

## License

MIT
