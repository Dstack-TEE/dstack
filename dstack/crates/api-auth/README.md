<!--
SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>

SPDX-License-Identifier: Apache-2.0
-->

# dstack-api-auth

Shared authentication primitives for dstack HTTP and RPC administration APIs.

HTTP integrations support:

- `Authorization: Bearer <token>`;
- a service-specific token header (`X-Admin-Token` for Gateway and
  `X-API-Token` for VMM);
- `Authorization: Basic ...` backed by a bcrypt Apache htpasswd file;
- optional GET-only `?token=` links for the Gateway and VMM dashboards.

Generate a compatible password file with:

```bash
htpasswd -B -c /etc/dstack/admin.htpasswd admin
```

Gateway's existing token configuration and environment variables remain
supported. VMM's existing `[auth] enabled` and `tokens` fields remain supported;
when enabled, authentication now covers the complete externally listening
Rocket server. The separate VMM host-vsock server is intentionally unaffected.

KMS continues to accept the existing SHA-256 `admin_token_hash` and protobuf
request token. Its comparison uses the constant-time verifier from this crate;
the public KMS application APIs are not placed behind operator HTTP Basic auth.
