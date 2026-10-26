// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { x25519 } from "@noble/curves/ed25519"

function hexToUint8Array(hex: string): Uint8Array {
  hex = hex.startsWith("0x") ? hex.slice(2) : hex
  return new Uint8Array(
    hex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) ?? [],
  )
}

function uint8ArrayToHex(buffer: Uint8Array): string {
  return Array.from(buffer)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
}

export interface EnvVar {
  key: string
  value: string
}

/**
 * ECIES-encrypt a set of environment variables against a recipient's x25519
 * public key. Works on Node 18+ and modern browsers — uses `globalThis.crypto`
 * (Web Crypto API) and @noble/curves.
 */
export async function encryptEnvVars(
  envs: EnvVar[],
  publicKeyHex: string,
): Promise<string> {
  const envsJson = JSON.stringify({ env: envs })

  const privateKey = x25519.utils.randomPrivateKey()
  const publicKey = x25519.getPublicKey(privateKey)

  const remotePubkey = hexToUint8Array(publicKeyHex)
  const shared = x25519.getSharedSecret(privateKey, remotePubkey)

  const importedShared = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(shared),
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"],
  )

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    importedShared,
    new TextEncoder().encode(envsJson),
  )

  const result = new Uint8Array(
    publicKey.length + iv.length + encrypted.byteLength,
  )
  result.set(publicKey)
  result.set(iv, publicKey.length)
  result.set(new Uint8Array(encrypted), publicKey.length + iv.length)

  return uint8ArrayToHex(result)
}
