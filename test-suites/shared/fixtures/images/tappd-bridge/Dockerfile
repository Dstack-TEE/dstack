# SPDX-License-Identifier: Apache-2.0
FROM scratch
COPY dstack-socket-bridge /dstack-socket-bridge
ENTRYPOINT ["/dstack-socket-bridge", "2000:/var/run/tappd.sock", "3000:/var/run/dstack.sock"]
