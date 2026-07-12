# SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

DOMAIN := local
TO := ./certs

.PHONY: clean run all certs

all:

certs: ${TO}

${TO}:
	mkdir -p ${TO}
	cargo run --bin certgen -- generate --domain ${DOMAIN} --output-dir ${TO}

run:
	$(MAKE) -C mkguest run

clean:
	rm -rf ${TO}
