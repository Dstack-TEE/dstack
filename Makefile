# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

.PHONY: help core core-check core-test sdk-test os os-yocto

help:
	@echo "dstack monorepo targets:"
	@echo "  core        build the Rust workspace"
	@echo "  core-check  check the Rust workspace"
	@echo "  core-test   test the Rust workspace"
	@echo "  sdk-test    run all public SDK tests"
	@echo "  os          build the guest OS with the default backend"
	@echo "  os-yocto    build the guest OS with Yocto"

core:
	cargo build --manifest-path dstack/Cargo.toml

core-check:
	cargo check --manifest-path dstack/Cargo.toml --workspace

core-test:
	cargo test --manifest-path dstack/Cargo.toml --workspace

sdk-test:
	cd sdk && ./run-tests.sh

os:
	./os/build.sh

os-yocto:
	./os/build.sh --backend yocto
