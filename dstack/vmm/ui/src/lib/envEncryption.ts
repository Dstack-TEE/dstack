// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { Aes256Gcm, CipherSuite, HkdfSha256 } from '@hpke/core';
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519';
import type { vmm as VmmTypes } from '../proto/vmm_rpc';

export type EnvEntry = { key: string; value: string };
type EnvPayload = { sealed_env?: Uint8Array; encrypted_env?: Uint8Array };
type KeyClient = {
  getSealedEnvPubKey(request: VmmTypes.IAppId): Promise<VmmTypes.ISealedEnvPubKeyResponse>;
  getAppEnvEncryptPubKey(request: VmmTypes.IAppId): Promise<VmmTypes.IPublicKeyResponse>;
};

/** Keep key retrieval on the authenticated, same-origin VMM transport. */
export async function encryptEnvPayload(
  client: KeyClient,
  envs: EnvEntry[],
  appId: Uint8Array,
  encryptLegacy: (envs: EnvEntry[], key: Uint8Array) => Promise<Uint8Array>,
  supportsSealedEnv: boolean,
): Promise<EnvPayload> {
  const legacyPayload = async () => {
    const legacy = await client.getAppEnvEncryptPubKey({ app_id: appId });
    return { encrypted_env: await encryptLegacy(envs, legacy.public_key) };
  };
  if (!supportsSealedEnv) return legacyPayload();
  const response = await client.getSealedEnvPubKey({ app_id: appId });
  const epoch = response.root_epoch;
  const appEpoch = response.app_epoch ?? 0;
  if (!Number.isInteger(appEpoch) || appEpoch < 0 || appEpoch > 0xffffffff) throw new Error('invalid app epoch');
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
    info: new TextEncoder().encode(`dstack-sealed-env-v1:${epoch}:${appEpoch}`),
  }, new TextEncoder().encode(JSON.stringify({ env: envs })));
  const base64 = (bytes: ArrayBuffer) => btoa(Array.from(new Uint8Array(bytes), (byte) => String.fromCharCode(byte)).join(''));
  return { sealed_env: new TextEncoder().encode(JSON.stringify({
    version: 1,
    root_epoch: epoch,
    app_epoch: appEpoch,
    enc: base64(enc),
    ciphertext: base64(ct),
  })) };
}
