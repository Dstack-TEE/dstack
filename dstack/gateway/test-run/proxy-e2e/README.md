<!--
SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>

SPDX-License-Identifier: Apache-2.0
-->

# Gateway proxy data-path suite

Runs the gateway, the origin server and the probe client in one container. They
have to share a network namespace: `insecure_localhost_backend` resolves the
backend address to `127.0.0.1` as the gateway itself sees it.

## Why the kTLS fallback arm runs in a second container

One arm asserts that a gateway configured for kTLS on a kernel without the TLS
ULP falls back to userspace instead of truncating a gated transfer at the gate.
The suite used to produce that condition with `sudo rmmod tls`, which cannot
work in a container and which took the module away from the whole host.

`notls-seccomp.json` makes `setsockopt(IPPROTO_TCP, TCP_ULP)` return
`ENOPROTOOPT` for one container instead, which is exactly what `probe_ktls()`
sees on a kernel without `CONFIG_TLS`. It touches nothing outside that
container and does not care what else on the machine is using TLS.

A seccomp profile is fixed when a container is created, so the arm needs its
own container rather than a restart of the main one.
