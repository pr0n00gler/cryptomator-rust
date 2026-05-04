.PHONY: clippy test build run gui

clippy:
	rustup component add clippy || true
	cargo clippy --all-targets --workspace -- -D warnings

test:
	cargo test

build-cli:
	cargo build --release

build-gui:
	cargo build --release --features gui --bin cryptomator-gui

build: clippy test build-cli build-gui
