// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { Aes256Gcm, CipherSuite, HkdfSha256 } from '@hpke/core';
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519';
import type { vmm as VmmTypes } from '../proto/vmm_rpc';
import { RpcError } from './vmmRpcClient';

export type EnvEntry = { key: string; value: string };
type EnvPayload = { sealed_env?: Uint8Array; encrypted_env?: Uint8Array };
type KeyClient = {
  getSealedEnvPubKey(request: VmmTypes.IAppId): Promise<VmmTypes.ISealedEnvPubKeyResponse>;
  getAppEnvEncryptPubKey(request: VmmTypes.IAppId): Promise<VmmTypes.IPublicKeyResponse>;
};

const missingService = 'Service not found: GetSealedEnvPubKey';

function isUnsupported(error: unknown): boolean {
  if (!(error instanceof RpcError) || ![400, 404].includes(error.status)) return false;
  if (error.message === missingService) return true;
  // The VMM forwards an older KMS's JSON RPC error through its binary RPC.
  const forwarded = /^Request failed with status=(?:400 Bad Request|404 Not Found), error=(.+)$/s.exec(error.message);
  if (!forwarded) return false;
  try {
    return JSON.parse(forwarded[1]).error === missingService;
  } catch {
    return false;
  }
}

/** Keep key retrieval on the authenticated, same-origin VMM transport. */
export async function encryptEnvPayload(
  client: KeyClient,
  envs: EnvEntry[],
  appId: Uint8Array,
  encryptLegacy: (envs: EnvEntry[], key: Uint8Array) => Promise<Uint8Array>,
): Promise<EnvPayload> {
  let response: VmmTypes.ISealedEnvPubKeyResponse;
  try {
    response = await client.getSealedEnvPubKey({ app_id: appId });
  } catch (error) {
    if (!isUnsupported(error)) throw error;
    const legacy = await client.getAppEnvEncryptPubKey({ app_id: appId });
    return { encrypted_env: await encryptLegacy(envs, legacy.public_key) };
  }
  const epoch = response.root_epoch;
  if (!Number.isInteger(epoch) || epoch < 0 || epoch > 0xffffffff || response.public_key?.length !== 32) {
    throw new Error('invalid sealed env public key response');
  }
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  const recipientPublicKey = await suite.kem.deserializePublicKey(new Uint8Array(response.public_key));
  const { enc, ct } = await suite.seal({
    recipientPublicKey,
    info: new TextEncoder().encode(`dstack-sealed-env-v1:${epoch}`),
  }, new TextEncoder().encode(JSON.stringify({ env: envs })));
  const base64 = (bytes: ArrayBuffer) => btoa(Array.from(new Uint8Array(bytes), (byte) => String.fromCharCode(byte)).join(''));
  return { sealed_env: new TextEncoder().encode(JSON.stringify({
    version: 1,
    root_epoch: epoch,
    enc: base64(enc),
    ciphertext: base64(ct),
  })) };
}
