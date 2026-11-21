// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Package dstack provides Go clients for the dstack guest agent API.
//
// The guest agent serves two API surfaces on one Unix socket
// (/var/run/dstack.sock), selected by URL path, and this package mirrors both:
//
//   - [DstackClient] (an alias for [DstackClientV1]) speaks /v1/<Method> and is
//     the current API: IssueCert, GetKey, Attest, AttestGpu, Info, and Version.
//   - [DstackClientV0] is the frozen v0.5.11 surface, kept compiling for
//     pre-0.6 applications and never extended.
//
// The package also carries the deployment-time helpers: compose hashing via
// [GetComposeHash], sealed environment encryption via [SealEnv], and KMS
// response verification via [VerifySealedEnvPublicKey] and
// [VerifyEnvEncryptPublicKeyWithTimestamp].
//
// RA-TLS certificate verification for dstack TEE applications lives in the
// separate module github.com/Dstack-TEE/dstack/sdk/go/ratls. The retired
// tappd-era client remains at github.com/Dstack-TEE/dstack/sdk/go/tappd,
// deprecated.
package dstack
