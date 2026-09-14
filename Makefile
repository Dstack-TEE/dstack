# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Submodules for the deprecated Yocto backend.
OS_YOCTO_SUBMODULES := \
	os/yocto/deps/bitbake \
	os/yocto/deps/openembedded-core \
	os/yocto/deps/meta-yocto \
	os/yocto/deps/meta-confidential-compute \
	os/yocto/deps/meta-virtualization \
	os/yocto/deps/meta-openembedded \
	os/yocto/deps/meta-rust-bin \
	os/yocto/deps/meta-security

.PHONY: help core core-check core-test sdk-test os os-image os-repro-check \
	os-image-mkosi os-repro-check-mkosi os-yocto os-deps os-image-yocto os-repro-check-yocto

help:
	@echo "dstack monorepo targets:"
	@echo "  core        build the Rust workspace"
	@echo "  core-check  check the Rust workspace"
	@echo "  core-test   test the Rust workspace with the simulator"
	@echo "  sdk-test    run all public SDK tests"
	@echo "  os          build the guest OS natively with the default (mkosi) backend"
	@echo "  os-image    build one production guest image with mkosi in the pinned container"
	@echo "  os-repro-check  build twice with mkosi and compare outputs byte for byte"
	@echo ""
	@echo "Deprecated Yocto targets (do not use for new work; use the mkosi targets above):"
	@echo "  os-yocto              build the guest OS natively with Yocto"
	@echo "  os-deps               initialize only the Yocto dependency submodules"
	@echo "  os-image-yocto        build one production guest image with Yocto"
	@echo "  os-repro-check-yocto  build twice with Yocto and compare outputs"

core:
	cargo build --manifest-path dstack/Cargo.toml

core-check:
	cargo check --manifest-path dstack/Cargo.toml --workspace

core-test:
	./dstack/run-tests.sh

sdk-test:
	cd sdk && ./run-tests.sh

os:
	./os/build.sh

# The mkosi backend vendors no submodules, so these do not depend on os-deps.
os-image:
	./os/mkosi/repro-build/repro-build.sh

os-repro-check:
	./os/mkosi/repro-build/repro-build.sh -c

# Aliases kept for existing callers.
os-image-mkosi: os-image

os-repro-check-mkosi: os-repro-check

# Deprecated Yocto backend. Kept only to rebuild existing Yocto images.
os-yocto:
	./os/build.sh --backend yocto

os-deps:
	git submodule update --init --depth 1 -- $(OS_YOCTO_SUBMODULES)

os-image-yocto: os-deps
	cd os/yocto/repro-build && ./repro-build.sh -n

os-repro-check-yocto: os-deps
	cd os/yocto/repro-build && ./repro-build.sh
