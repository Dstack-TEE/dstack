# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
CARGO_TARGET_DIR ?= target
SELF_EXE := $(CARGO_TARGET_DIR)/release/local-key-provider
MANIFEST := local-key-provider.manifest
PROVIDER_DIR ?= ..
WORKSPACE_DIR ?= $(abspath $(PROVIDER_DIR)/..)

SGX ?= 1
DEBUG ?= 0

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL := debug
RUST_LOG := debug
else
GRAMINE_LOG_LEVEL := error
RUST_LOG ?= info
endif

.PHONY: all
all: $(SELF_EXE) $(MANIFEST)
ifeq ($(SGX),1)
all: $(MANIFEST).sgx local-key-provider.sig
endif

PROVIDER_SOURCES := $(shell find $(PROVIDER_DIR)/src -type f -name '*.rs')

$(SELF_EXE): $(WORKSPACE_DIR)/Cargo.toml $(WORKSPACE_DIR)/Cargo.lock \
	$(PROVIDER_DIR)/Cargo.toml $(PROVIDER_SOURCES)
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
	CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
	CARGO_PROFILE_RELEASE_LTO=true \
	CARGO_PROFILE_RELEASE_PANIC=abort \
	CARGO_PROFILE_RELEASE_STRIP=true \
	cargo build --locked --release --manifest-path $(WORKSPACE_DIR)/Cargo.toml \
		-p local-key-provider

$(MANIFEST): local-key-provider.manifest.template $(SELF_EXE)
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dself_exe=$(SELF_EXE) \
		-Drust_log=$(RUST_LOG) \
		$< $@

$(MANIFEST).sgx local-key-provider.sig: sgx-sign
	@:

.INTERMEDIATE: sgx-sign
sgx-sign: $(MANIFEST) $(SELF_EXE)
	gramine-sgx-sign --manifest $(MANIFEST) --output $(MANIFEST).sgx

ifeq ($(SGX),1)
GRAMINE ?= gramine-sgx
else
GRAMINE ?= gramine-direct
endif

.PHONY: run-provider
run-provider: all
	$(GRAMINE) local-key-provider

.PHONY: clean
clean:
	$(RM) local-key-provider.sig $(MANIFEST) $(MANIFEST).sgx

.PHONY: distclean
distclean: clean
	$(RM) -r $(CARGO_TARGET_DIR)
