# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

FROM oven/bun:1.4.3-alpine@sha256:629e17411f1f129dbec3af78d5af9c9f2a937435c80349437206c6b0b7422373
WORKDIR /app

ARG DSTACK_REV
ARG DSTACK_BRANCH=next

RUN apk add --no-cache git
RUN git clone --branch ${DSTACK_BRANCH} https://github.com/Dstack-TEE/dstack.git && \
    cd dstack && \
    git checkout ${DSTACK_REV}
WORKDIR /app/dstack/dstack/kms/auth-mock
RUN bun install --frozen-lockfile
CMD ["bun", "index.ts"]
