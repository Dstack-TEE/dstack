.PHONY: install lint format type-check type-check-tests test check-all verify

# Install dependencies including linting tools
install:
	pdm install -G lint

# Run all formatters (using PDM scripts)
format:
	pdm run fmt

# Alias for format
fmt: format

# Run linting tools (using PDM scripts)
lint:
	pdm run lint

# Run type checking only
type-check:
	pdm run mypy src/

# Run type checking on tests specifically  
type-check-tests:
	pdm run mypy tests/test_mypy_check.py tests/test_typing.py

# Run tests
test:
	@if [ -z "$$DSTACK_SIMULATOR_ENDPOINT" ]; then \
		echo "error: DSTACK_SIMULATOR_ENDPOINT environment variable is not set"; \
		exit 1; \
	fi
	@if [ -z "$$TAPPD_SIMULATOR_ENDPOINT" ]; then \
		echo "error: TAPPD_SIMULATOR_ENDPOINT environment variable is not set"; \
		exit 1; \
	fi
	@if [[ "$$DSTACK_SIMULATOR_ENDPOINT" == /* ]] && [ ! -e "$$DSTACK_SIMULATOR_ENDPOINT" ]; then \
		echo "error: dstack socket file $$DSTACK_SIMULATOR_ENDPOINT does not exist"; \
		exit 1; \
	fi
	@if [[ "$$TAPPD_SIMULATOR_ENDPOINT" == /* ]] && [ ! -e "$$TAPPD_SIMULATOR_ENDPOINT" ]; then \
		echo "error: tappd socket file $$TAPPD_SIMULATOR_ENDPOINT does not exist"; \
		exit 1; \
	fi
	pdm run test

# Run all checks (format, lint, skip test)
check-all:
	pdm run fmt
	pdm run lint

# Check code without fixing (for CI)
check:
	pdm run check

# Run verification without formatting (skip test)
verify:
	pdm run check
