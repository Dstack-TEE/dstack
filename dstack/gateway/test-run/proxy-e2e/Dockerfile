# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# The proxy data-path suite runs the gateway, the origin server and the probe
# client together in one container, because they must share a network
# namespace: `insecure_localhost_backend` resolves the backend to 127.0.0.1 as
# seen by the gateway itself.
FROM debian:bookworm-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      --no-install-recommends \
      python3 openssl iproute2 iputils-ping curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /suite
COPY dstack-gateway /usr/local/bin/dstack-gateway
RUN chmod +x /usr/local/bin/dstack-gateway
COPY test_proxy.sh /suite/test_proxy.sh
COPY proxy /suite/proxy
RUN chmod +x /suite/test_proxy.sh

ENV GATEWAY_BIN=/usr/local/bin/dstack-gateway
ENTRYPOINT ["/suite/test_proxy.sh"]
