// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// HPKE's Node fallback uses the browser's native Web Crypto in this bundle.
export const webcrypto = globalThis.crypto;
