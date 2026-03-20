# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

FROM oven/bun:1-alpine
WORKDIR /app

ARG DSTACK_REV
ARG DSTACK_BRANCH=master

RUN apk add --no-cache git
RUN git clone --branch ${DSTACK_BRANCH} https://github.com/Dstack-TEE/dstack.git && \
    cd dstack && \
    git checkout ${DSTACK_REV}
WORKDIR /app/dstack/kms/auth-mock
RUN bun install --frozen-lockfile
CMD ["bun", "index.ts"]
