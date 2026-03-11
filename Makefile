.PHONY: setup test lint clean demo build debug verify test-swarm

setup:
	@if [ ! -f policy.json ]; then cp policy.json.example policy.json && echo "Created policy.json from policy.json.example"; fi
	docker compose build
	cd sdks/python && pip install -e .
	cd sdks/nodejs && npm install
	cd dashboard && npm install

build:
	cargo build --manifest-path core/proxy/Cargo.toml
	cargo build --manifest-path core/verifier/Cargo.toml
	cargo build --manifest-path dev/cli/Cargo.toml
	cargo build --manifest-path tools/catenar-verify/Cargo.toml
	cd sdks/nodejs && npm run build

test:
	@set -e; \
	cd core/verifier && cargo test && echo "Verifier: OK"; \
	cd ../proxy && cargo test && echo "Proxy: OK"; \
	cd ../../tools/catenar-verify && cargo test && echo "catenar-verify: OK"; \
	cd ../../sdks/python && pytest && echo "Python SDK: OK"; \
	cd ../../dashboard && npm test && npm run lint && echo "Dashboard: OK"; \
	echo ""; echo "All tests passed."

lint:
	cd core/proxy && cargo fmt --check
	cd core/verifier && cargo fmt --check
	cd dev/cli && cargo fmt --check
	cd tools/catenar-verify && cargo fmt --check
	cd dashboard && npm run lint

demo:
	@if [ ! -f policy.json ]; then cp policy.json.example policy.json && echo "Created policy.json from policy.json.example"; fi
	docker compose up -d --wait verifier proxy web prometheus grafana
	@echo ""
	@echo "Dashboard: http://localhost:3001 | Demo: cd sdks/python && python agent.py --demo"
	@echo "Set CATENAR_DEMO=1 for auto proxy/CA config. See docs/demo/getting-started.md"

debug:
	cargo run --manifest-path dev/cli/Cargo.toml -- debug watch

verify:
	cargo run --manifest-path tools/catenar-verify/Cargo.toml -- ./data/proxy-trace.jsonl

test-swarm:
	@if [ ! -f policy.json ]; then cp policy.json.example policy.json; fi
	docker compose up -d --wait verifier proxy
	python examples/swarm_demo.py || (echo "Swarm demo failed"; exit 1)

clean:
	docker compose down
	rm -f sdks/python/catenar-trace-wal.jsonl core/verifier/policies.db
