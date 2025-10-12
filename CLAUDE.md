# Better Auth - Rust Implementation

## Project Context

This is a **Rust implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth), a multi-repository authentication protocol.

This implementation includes **both client and server** components and was ported from the TypeScript reference implementation.

## Related Repositories

**Specification:** [better-auth](https://github.com/jasoncolburne/better-auth)

**Reference Implementation:** [better-auth-ts](https://github.com/jasoncolburne/better-auth-ts) (TypeScript)

**Other Implementations:**
- Full: [Python](https://github.com/jasoncolburne/better-auth-py)
- Server Only: [Go](https://github.com/jasoncolburne/better-auth-go), [Ruby](https://github.com/jasoncolburne/better-auth-rb)
- Client Only: [Swift](https://github.com/jasoncolburne/better-auth-swift), [Dart](https://github.com/jasoncolburne/better-auth-dart), [Kotlin](https://github.com/jasoncolburne/better-auth-kt)

## Repository Structure

This repository is a **git submodule** of the parent [better-auth](https://github.com/jasoncolburne/better-auth) specification repository. The parent repository includes all 8 language implementations as submodules and provides orchestration scripts for cross-implementation testing.

### Standardized Build System

All implementations use standardized `Makefile` targets for consistency:

```bash
make setup          # Fetch dependencies (cargo fetch)
make test           # Run tests (cargo test)
make type-check     # Type check (cargo check)
make lint           # Run linter (cargo clippy)
make format         # Format code (cargo fmt)
make format-check   # Check formatting (cargo fmt --check)
make build          # Build project (cargo build --release)
make clean          # Clean artifacts (cargo clean)
make server         # Run example server (cargo run --example server)
```

### Parent Repository Orchestration

The parent repository provides scripts in `scripts/` for running operations across all implementations:

- `scripts/run-setup.sh` - Setup all implementations
- `scripts/run-unit-tests.sh` - Run tests across all implementations
- `scripts/run-type-checks.sh` - Run type checkers across all implementations
- `scripts/run-lints.sh` - Run linters across all implementations
- `scripts/run-format-checks.sh` - Check formatting across all implementations
- `scripts/run-integration-tests.sh` - Run cross-language integration tests
- `scripts/run-all-checks.sh` - Run all checks in sequence
- `scripts/pull-repos.sh` - Update all submodules

These scripts automatically skip implementations where tooling is not available.

## Architecture

### Directory Structure

```
src/
├── lib.rs              # Main library exports
├── api/                # Client and Server implementations
│   ├── mod.rs
│   ├── client.rs       # BetterAuthClient struct
│   └── server.rs       # BetterAuthServer struct
├── interfaces/         # Protocol trait definitions
│   ├── mod.rs
│   ├── crypto.rs       # Hasher, Noncer, Verifier, SigningKey, VerificationKey traits
│   ├── encoding.rs     # Timestamper, TokenEncoder, IdentityVerifier traits
│   ├── io.rs           # Network trait
│   ├── paths.rs        # AuthenticationPaths trait
│   └── storage.rs      # Client and server storage traits
├── messages/           # Protocol message types
│   ├── mod.rs
│   ├── message.rs      # Base message types
│   ├── request.rs      # Base request types
│   ├── response.rs     # Base response types
│   ├── account.rs      # Account protocol messages
│   ├── device.rs       # Device protocol messages
│   ├── session.rs      # Session protocol messages
│   └── access.rs       # Access protocol messages
└── tests/              # Test suite
    ├── mod.rs
    └── implementation/ # Reference trait implementations

tests/                  # Integration tests
└── api_test.rs

examples/               # Example implementations
└── server.rs
```

### Key Components

**BetterAuthClient** (`src/api/client.rs`)
- Implements all client-side protocol operations
- Manages authentication state and key rotation
- Handles token lifecycle
- Composes crypto, storage, and encoding traits

**BetterAuthServer** (`src/api/server.rs`)
- Implements all server-side protocol operations
- Validates requests and manages device state
- Issues and validates tokens
- Composes crypto, storage, and encoding traits

**Message Types** (`src/messages/`)
- Protocol message structs with `serde` serialization
- Type-safe request/response pairs
- Derives: `Debug`, `Clone`, `Serialize`, `Deserialize`

**Trait Definitions** (`src/interfaces/`)
- Traits define contracts for crypto, storage, encoding, and I/O
- Enable pluggable implementations
- Use trait objects or generic parameters

## Rust-Specific Patterns

### Trait-Based Architecture

This implementation heavily uses Rust traits to define interfaces:
- `Hasher`, `Noncer`, `Verifier` for crypto operations
- `SigningKey`, `VerificationKey` for key operations
- Storage traits for client and server stores
- `Network`, `Timestamper`, `TokenEncoder`, etc.

Traits can be used as:
- Trait bounds on generic parameters: `T: Hasher`
- Trait objects: `Box<dyn Hasher>`

### Type Safety and Ownership

Leverages Rust's ownership system:
- Borrowed references (`&str`, `&[u8]`) for read-only access
- Owned types (`String`, `Vec<u8>`) for data that needs to be stored
- Careful lifetime management
- No null values - use `Option<T>` for optional values

### Error Handling

Uses `Result<T, E>` for error handling:
- Custom error types for different failure modes
- `?` operator for error propagation
- Pattern matching for explicit error handling
- No exceptions - all errors are values

### Serde for Serialization

All message types use `serde` for serialization:
- `#[derive(Serialize, Deserialize)]` on message structs
- JSON serialization by default
- Easy integration with other formats (CBOR, MessagePack, etc.)

### Async with Tokio

All async operations use the `tokio` runtime:
- `async fn` for asynchronous functions
- `.await` for awaiting futures
- `#[tokio::test]` for async tests
- All trait methods that do I/O are async

### Strong Type System

Leverages Rust's type system for safety:
- Newtype pattern for domain types
- Enums for variant data
- Generic parameters with trait bounds
- Zero-cost abstractions

## Reference Implementations

The `tests/implementation/` directory contains reference implementations using:
- **blake3** for cryptographic hashing
- **p256** for ECDSA P-256 signing/verification
- **rand** for secure random generation
- **chrono** for timestamps
- **serde_json** for JSON serialization
- In-memory `HashMap` stores

These demonstrate how to implement the protocol traits in Rust.

## Testing

### Unit Tests
Tests are in `src/tests/` and use the Rust test framework:
- Test all protocol operations
- Use reference implementations
- Cover client and server flows

Run with: `cargo test`

### Integration Tests
Integration tests are in `tests/`:
- End-to-end tests covering full protocol flows
- Test client-server interactions

Run with: `cargo test --test api_test`

### Running Tests
```bash
cargo test                    # Run all tests
cargo test --verbose          # Verbose output
cargo test api_test           # Specific test
cargo test --release          # Optimized build
```

## Usage Patterns

### Client Initialization

```rust
use better_auth::BetterAuthClient;

let client = BetterAuthClient::new(ClientConfig {
    crypto: CryptoConfig {
        hasher: Box::new(your_hasher),
        noncer: Box::new(your_noncer),
        response_public_key: server_public_key,
    },
    encoding: EncodingConfig {
        timestamper: Box::new(your_timestamper),
    },
    io: IoConfig {
        network: Box::new(your_network),
    },
    paths: your_paths,
    store: StoreConfig {
        identity: Box::new(identity_store),
        device: Box::new(device_store),
        key: KeyStoreConfig {
            authentication: Box::new(auth_key_store),
            access: Box::new(access_key_store),
        },
        token: TokenStoreConfig {
            access: Box::new(token_store),
        },
    },
});
```

### Server Initialization

```rust
use better_auth::BetterAuthServer;

let server = BetterAuthServer::new(ServerConfig {
    crypto: CryptoConfig {
        hasher: Box::new(your_hasher),
        key_pair: KeyPairConfig {
            response: Box::new(response_signing_key),
            access: Box::new(access_signing_key),
        },
        verifier: Box::new(your_verifier),
    },
    encoding: EncodingConfig {
        identity_verifier: Box::new(your_identity_verifier),
        timestamper: Box::new(your_timestamper),
        token_encoder: Box::new(your_token_encoder),
    },
    expiry: ExpiryConfig {
        access_in_minutes: 15,
        refresh_in_hours: 24,
    },
    store: StoreConfig {
        access: AccessStoreConfig {
            key_hash: Box::new(access_key_hash_store),
        },
        authentication: AuthenticationStoreConfig {
            key: Box::new(auth_key_store),
            nonce: Box::new(nonce_store),
        },
        recovery: RecoveryStoreConfig {
            hash: Box::new(recovery_hash_store),
        },
    },
});
```

### Client Operations

```rust
// Create account
client.create_account(&recovery_hash).await?;

// Authenticate
client.authenticate().await?;

// Make access request
let response = client.make_access_request("/api/resource", request_data).await?;

// Rotate authentication key
client.rotate_authentication_key().await?;

// Refresh access token
client.refresh_access_token().await?;
```

### Server Operations

```rust
// Handle request
let response = server.handle_request(request).await?;
```

## Development Workflow

### Building
```bash
cargo build               # Debug build
cargo build --release     # Release build
```

### Testing
```bash
cargo test                # Run all tests
cargo test --verbose      # Verbose output
cargo test --release      # Test optimized build
```

### Linting & Formatting
```bash
cargo fmt                 # Format code
cargo clippy              # Lint with clippy
cargo clippy --all-targets --all-features -- -D warnings  # Strict linting
```

### Documentation
```bash
cargo doc --open          # Generate and open docs
```

## Integration with Other Implementations

This Rust implementation can be used:
- As a client for testing against Go/Python/Ruby servers
- As a server for testing TypeScript/Python/client-only implementations

## Making Changes

When making changes to this implementation:
1. Update the code
2. Run tests: `cargo test`
3. Run clippy: `cargo clippy`
4. Format code: `cargo fmt`
5. If protocol changes: sync with the TypeScript reference implementation
6. If breaking changes: update other implementations
7. Update this CLAUDE.md if architecture changes

## Key Files to Know

- `src/api/client.rs` - All client logic
- `src/api/server.rs` - All server logic
- `src/messages/` - Protocol message definitions
- `src/interfaces/` - Trait definitions
- `tests/api_test.rs` - Integration tests
- `src/tests/implementation/` - Reference trait implementations
- `examples/server.rs` - Example HTTP server

## Rust Edition and Features

- Uses Rust 2021 edition
- Requires async runtime (tokio)
- Core dependencies: serde, tokio, async-trait
- Crypto dependencies: blake3, p256, rand

## Future Work

### Dependency Management
- **Minimize production dependencies**: Review `Cargo.toml` to ensure only essential dependencies are included in the main library. Consider:
  - Moving test-only dependencies to `[dev-dependencies]`
  - Making crypto implementations optional via feature flags
  - Reducing the dependency tree for minimal deployments

### Code Organization
- **Move example implementations out of src/**: Currently, reference implementations are in `src/tests/implementation/`. Consider:
  - Moving to a top-level `examples/` or `reference/` directory if Rust's module system permits
  - Ensuring these implementations don't increase compile time or binary size for library consumers
  - Making example implementations opt-in via feature flags
  - Separating test fixtures from production code more clearly

These changes would improve the library's modularity and reduce overhead for production users who want to bring their own crypto and storage implementations.
