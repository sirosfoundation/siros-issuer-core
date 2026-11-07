.POSIX:
.SILENT:

CARGO ?= cargo

help: ## Show this help
	grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk ' { printf "%-12s %s\n", $$1, $$NF }'

fmt: ## Format all code
	$(CARGO) fmt --all

check: ## Format check, clippy, tests
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --locked --workspace --all-targets -- -D warnings
	$(CARGO) test --locked --workspace

run: ## Run the service against the fixture catalog
	$(CARGO) run -p siros-issuer-service -- testdata/config.fixtures.toml

clean: ## Clean build artifacts
	$(CARGO) clean

.PHONY: help fmt check run clean
