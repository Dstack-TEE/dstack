// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Helpers both client surfaces need. Kept out of `client-v0.ts` so the v1
// client does not have to import from the frozen module to reach them.

import fs from 'fs'

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
