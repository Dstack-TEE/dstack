# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

OS_YOCTO_SUBMODULES := \
	os/yocto/deps/bitbake \
	os/yocto/deps/openembedded-core \
	os/yocto/deps/meta-yocto \
	os/yocto/deps/meta-confidential-compute \
	os/yocto/deps/meta-virtualization \
	os/yocto/deps/meta-openembedded \
	os/yocto/deps/meta-rust-bin \
	os/yocto/deps/meta-security

.PHONY: help core core-check core-test sdk-test os os-yocto os-deps os-image os-repro-check \
	os-image-mkosi os-repro-check-mkosi

help:
	@echo "dstack monorepo targets:"
	@echo "  core        build the Rust workspace"
	@echo "  core-check  check the Rust workspace"
	@echo "  core-test   test the Rust workspace with the simulator"
	@echo "  sdk-test    run all public SDK tests"
	@echo "  os          build the guest OS natively with the default backend"
	@echo "  os-yocto    build the guest OS natively with Yocto"
	@echo "  os-deps     initialize only the Yocto dependency submodules"
	@echo "  os-image    build one production guest image in the pinned container"
	@echo "  os-repro-check  build twice and compare reproducible outputs"
	@echo "  os-image-mkosi  build one production guest image with the mkosi backend"
	@echo "  os-repro-check-mkosi  build twice with mkosi and compare outputs"

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

os-yocto:
	./os/build.sh --backend yocto

os-deps:
	git submodule update --init --depth 1 -- $(OS_YOCTO_SUBMODULES)

os-image: os-deps
	cd os/yocto/repro-build && ./repro-build.sh -n

os-repro-check: os-deps
	cd os/yocto/repro-build && ./repro-build.sh

# The mkosi backend vendors no submodules, so these do not depend on os-deps.
os-image-mkosi:
	./os/mkosi/repro-build/repro-build.sh

os-repro-check-mkosi:
	./os/mkosi/repro-build/repro-build.sh -c
