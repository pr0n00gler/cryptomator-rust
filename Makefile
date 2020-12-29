.PHONY: clippy test build run

clippy:
	rustup component add clippy || true
	cargo clippy --all-targets --all-features --workspace -- -D warnings

test:
	cargo test -- --test-threads 1

build: clippy test
	cargo build

run: build
	cargo run