.PHONY: setup test type-check lint format format-check clean server test-integration build

setup:
	cargo fetch

test:
	cargo test --test api_test --test token_test

type-check:
	cargo check

lint:
	cargo clippy -- -Dwarnings

format:
	cargo fmt

format-check:
	cargo fmt --check

server:
	cargo run --example server

test-integration:
	cargo test --test integration_test

build:
	cargo build --release

clean:
	cargo clean
