#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
else
    python3 -m venv .venv
    source .venv/bin/activate
    pip install requests eth_keys cryptography "eth-hash[pycryptodome]"
    cp src/vmm-cli.py .venv/bin/
    ln -sf vmm-cli.py .venv/bin/vmm
fi
