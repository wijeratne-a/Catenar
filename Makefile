.PHONY: setup test lint clean demo build debug verify

setup:
	docker compose build
	cd sdks/python && pip install -e .
	cd sdks/nodejs && npm install
	cd dashboard && npm install

build:
	cargo build --manifest-path core/proxy/Cargo.toml
	cargo build --manifest-path core/verifier/Cargo.toml
	cargo build --manifest-path dev/cli/Cargo.toml
	cargo build --manifest-path tools/aegis-verify/Cargo.toml
	cd sdks/nodejs && npm run build

test:
	cd core/verifier && cargo test
	cd core/proxy && cargo test
	cd tools/aegis-verify && cargo test
	cd sdks/python && pytest
	cd dashboard && npm run lint

lint:
	cd core/proxy && cargo fmt --check
	cd core/verifier && cargo fmt --check
	cd dev/cli && cargo fmt --check
	cd tools/aegis-verify && cargo fmt --check
	cd dashboard && npm run lint

demo:
	docker compose up -d verifier proxy web prometheus grafana
	@echo "See docs/demo/getting-started.md"

debug:
	cargo run --manifest-path dev/cli/Cargo.toml -- debug watch

verify:
	cargo run --manifest-path tools/aegis-verify/Cargo.toml -- ./data/proxy-trace.jsonl

clean:
	docker compose down
	rm -f sdks/python/aegis-trace-wal.jsonl core/verifier/policies.db
