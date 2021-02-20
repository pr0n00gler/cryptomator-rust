.PHONY: clippy test build run

clippy:
	rustup component add clippy || true
	cargo clippy --all-targets --all-features --workspace -- -D warnings

test:
	cargo test

build: clippy test
	cargo build --release

run:
	cargo run