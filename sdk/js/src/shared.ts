// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Helpers both client surfaces need. Kept out of `client-v0.ts` so the v1
// client does not have to import from the frozen module to reach them.

import fs from 'fs'

/** An even number of hex digits, and nothing else. */
const HEX_ONLY = /^(?:[0-9a-fA-F]{2})*$/

export type Hex = `${string}`

export function to_hex(data: string | Buffer | Uint8Array): string {
  if (typeof data === 'string') {
    return Buffer.from(data).toString('hex');
  }
  if (data instanceof Uint8Array) {
    return Buffer.from(data).toString('hex');
  }
  return (data as Buffer).toString('hex');
}

/** Socket paths the clients probe, legacy first, then the namespaced variants. */
const DSTACK_SOCKET_PATHS = [
  '/var/run/dstack.sock',
  '/run/dstack.sock',
  '/var/run/dstack/dstack.sock',
  '/run/dstack/dstack.sock',
]

/**
 * A prpc handler reports failure in the response body rather than by refusing to
 * answer, so every method has to look for it; an unchecked call would hand the
 * caller a response object with every field missing.
 */
export function throwOnRpcError(result: unknown): void {
  if (result && typeof result === 'object' && 'error' in result) {
    throw new Error(String((result as { error: unknown }).error))
  }
}

/**
 * Resolve the socket or URL a client talks to.
 *
 * Shared by both clients because they address the same agent: v0 and v1 are two
 * mounts on one socket, so probing separate paths per surface would only give
 * them a way to disagree about where the agent is.
 */
export function resolveDstackEndpoint(endpoint: string | undefined): string {
  if (endpoint === undefined) {
    if (process.env.DSTACK_SIMULATOR_ENDPOINT) {
      console.warn(`Using simulator endpoint: ${process.env.DSTACK_SIMULATOR_ENDPOINT}`)
      endpoint = process.env.DSTACK_SIMULATOR_ENDPOINT
    } else {
      endpoint = DSTACK_SOCKET_PATHS.find(p => fs.existsSync(p)) ?? DSTACK_SOCKET_PATHS[0]
    }
  }
  if (endpoint.startsWith('/') && !fs.existsSync(endpoint)) {
    throw new Error(`Unix socket file ${endpoint} does not exist`);
  }
  return endpoint
}

/**
 * Decode a wire hex string, or say which field was malformed.
 *
 * Strict on purpose. Node's hex decoder stops at the first pair it cannot
 * parse and returns the prefix it managed, without error: `Buffer.from(
 * '0102zz', 'hex')` is two bytes, and an odd-length string loses its last
 * digit. These fields are private keys, signature chain links and application
 * identity -- handing back a silently truncated one is worse than throwing,
 * and Rust, Python and Go all refuse the same input.
 */
export function decode_hex(value: unknown, field: string): Uint8Array {
  // The type check is not redundant with the regex, and dropping it is a
  // silent-wrong-value bug rather than a style regression. `RegExp.test`
  // stringifies its argument, so a one-element array passes -- `['00112233']`
  // becomes `'00112233'` -- and `Buffer.from` then ignores the `'hex'`
  // argument for a non-string input and coerces the elements as octets:
  // `Number('00112233') & 0xff`, one attacker-chosen byte, no error. TypeScript
  // cannot stop this because a JSON response is `any` at runtime.
  if (typeof value !== 'string') {
    throw new Error(
      `the agent returned a malformed ${field}: expected a hex string, got ${
        value === null ? 'null' : Array.isArray(value) ? 'an array' : typeof value}`
    )
  }
  if (!HEX_ONLY.test(value)) {
    throw new Error(
      `the agent returned a malformed ${field}: expected an even-length hex string`
    )
  }
  return new Uint8Array(Buffer.from(value, 'hex'))
}

/**
 * Decode a `bytes` field the proto declares required.
 *
 * Absence is an error rather than the empty default: `app_id` and `key` are
 * answers the agent always has, so a response without one is a response that
 * did not come from a working agent. An empty *string* still decodes to zero
 * bytes, which is what every other SDK does with it.
 */
export function from_hex(value: unknown, field: string): Uint8Array {
  if (value === undefined) {
    throw new Error(`the agent returned no ${field}`)
  }
  return decode_hex(value, field)
}

/**
 * Read a `string` field the response is meaningless without.
 *
 * A bundle's `vendor` and `format` are what a caller dispatches on to pick a
 * verifier, so handing back `undefined` there does not degrade the answer, it
 * routes the evidence to no verifier at all -- quietly, since `undefined`
 * matches no `case`. Rust and Python both make these required.
 */
export function require_string(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new Error(
      `the agent returned a malformed ${field}: expected a string, got ${
        value === undefined ? 'nothing'
          : value === null ? 'null'
          : Array.isArray(value) ? 'an array' : typeof value}`
    )
  }
  return value
}

/**
 * Read a `repeated` field, or say which one was not a list.
 *
 * `Array.isArray` rather than a truthiness check: a bare `.map()` on a `null`
 * or absent field throws `TypeError: Cannot read properties of null`, which
 * names no field and reads like an SDK bug rather than a bad response.
 *
 * `whenAbsent` follows the proto. A missing `boottime_gpu_evidence` is the
 * empty list, because the field is only populated when asked for; a missing
 * `bundles` or `signature_chain` is a malformed response, because those are
 * the whole answer of the call that returns them.
 */
export function to_list(
  value: unknown, field: string, whenAbsent: 'empty' | 'error',
): unknown[] {
  if (value === undefined && whenAbsent === 'empty') {
    return []
  }
  if (!Array.isArray(value)) {
    throw new Error(`the agent returned a malformed ${field}: expected a list`)
  }
  return value
}
