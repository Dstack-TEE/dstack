# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Built from this directory, so the image carries exactly the checked-out
# source and lockfile rather than a clone fetched at build time.
FROM oven/bun:1.4.4-alpine@sha256:4cf82f5686b196504fe119db3fcd9185b191f82ece82c40680e597228ec6070a AS deps
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production --ignore-scripts

FROM oven/bun:1.4.4-alpine@sha256:4cf82f5686b196504fe119db3fcd9185b191f82ece82c40680e597228ec6070a
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json index.ts ./
ARG GIT_REV=unknown
LABEL org.opencontainers.image.revision="${GIT_REV}"
ENV NODE_ENV=production
# The KMS webhook default (`kms.toml`) is http://auth-api:8000.
ENV PORT=8000
EXPOSE 8000
USER bun
CMD ["bun", "index.ts"]
