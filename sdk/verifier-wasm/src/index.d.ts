// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

export interface VerifyTdxLiteOsInput {
  mrtd: string
  rtmr0: string
  rtmr1: string
  rtmr2: string
  eventLog: string
  vmConfig: string
}

export interface VerifyTdxLiteOsResult {
  ok: boolean
  osImageHash: string | null
  reason: string | null
}

/**
 * Verify a dstack TDX lite CVM's OS against already-verified MRTD/RTMR0-2.
 *
 * MRs are hex (any case). `eventLog` and `vmConfig` are the GetQuote
 * `event_log` / `vm_config` strings verbatim. Does not judge os_image_hash
 * approval, DCAP quote validity, or RTMR3.
 *
 * Never throws: bad input and wasm traps return `{ ok: false, ... }`.
 */
export function verifyTdxLiteOs(input: VerifyTdxLiteOsInput): VerifyTdxLiteOsResult
