// SPDX-FileCopyrightText: © 2024 Nethermind <contact@nethermind.io>
// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

module github.com/Dstack-TEE/dstack/sdk/go/dstack

go 1.25.0

require (
	github.com/cloudflare/circl v1.6.4
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1
	github.com/ethereum/go-ethereum v1.17.4
	golang.org/x/crypto v0.52.0
)

require (
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251001021608-1fe7b43fc4d6 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

// sdk/go v0.6.0 also shipped this package. Requiring the package-less v0.6.1
// makes minimal version selection drop that copy for importers still pinning
// v0.6.0, avoiding an "ambiguous import" error. Nothing imports sdk/go, so
// `go mod tidy` removes this line; keep it.
require github.com/Dstack-TEE/dstack/sdk/go v0.6.1

// Resolve the parent locally until sdk/go/v0.6.1 is tagged; replace
// directives are ignored by importers.
replace github.com/Dstack-TEE/dstack/sdk/go => ../
