import { x25519 } from "@noble/curves/ed25519"
import crypto from 'crypto'

// Convert hex string to Uint8Array
function hexToUint8Array(hex: string) {
  hex = hex.startsWith("0x") ? hex.slice(2) : hex;
  return new Uint8Array(
    hex.match(/.{1,2}/g)?.map((byte: string) => parseInt(byte, 16)) ?? [],
  );
}

function uint8ArrayToHex(buffer: Uint8Array) {
  return Array.from(buffer)
    .map((byte: number) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export interface EnvVar {
  key: string
  value: string
}

// Encrypt environment variables
export async function encryptEnvVars(envs: EnvVar[], publicKeyHex: string) {
  // Prepare environment data
  const envsJson = JSON.stringify({ env: envs });

  // Generate private key and derive public key
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);

  // Generate shared key
  const remotePubkey = hexToUint8Array(publicKeyHex);
  const shared = x25519.getSharedSecret(privateKey, remotePubkey);

  // Import shared key for AES-GCM
  const importedShared = await crypto.subtle.importKey(
    "raw",
    shared,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"],
  );

  // Encrypt the data
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    importedShared,
    new TextEncoder().encode(envsJson),
  );

  // Combine all components
  const result = new Uint8Array(
    publicKey.length + iv.length + encrypted.byteLength,
  );

  result.set(publicKey);
  result.set(iv, publicKey.length);
  result.set(new Uint8Array(encrypted), publicKey.length + iv.length);

  return uint8ArrayToHex(result);
}