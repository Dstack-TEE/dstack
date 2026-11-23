// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Deprecated: tappd is retired; use github.com/Dstack-TEE/dstack/sdk/go/dstack.
module github.com/Dstack-TEE/dstack/sdk/go/tappd

go 1.24.0

// sdk/go v0.6.0 also shipped this package. Requiring the package-less v0.6.1
// makes minimal version selection drop that copy for importers still pinning
// v0.6.0, avoiding an "ambiguous import" error. Nothing imports sdk/go, so
// `go mod tidy` removes this line; keep it.
require github.com/Dstack-TEE/dstack/sdk/go v0.6.1

// Resolve the parent locally until sdk/go/v0.6.1 is tagged; replace
// directives are ignored by importers.
replace github.com/Dstack-TEE/dstack/sdk/go => ../
