.PHONY: clippy test build run gui

clippy:
	rustup component add clippy || true
	cargo clippy --all-targets --workspace -- -D warnings

test:
	cargo test

build: clippy test
	cargo build --release

run:
	cargo run

gui: clippy test
	cargo build --release --features gui --bin cryptomator-gui

run-gui:
	cargo run --features gui --bin cryptomator-gui