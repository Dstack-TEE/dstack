// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { Aes256Gcm, CipherSuite, HkdfSha256 } from '@hpke/core';
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519';
import type { vmm as VmmTypes } from '../proto/vmm_rpc';

export type EnvEntry = { key: string; value: string; spec?: string };
type EnvPayload = { sealed_env?: Uint8Array; encrypted_env?: Uint8Array };
type KeyClient = {
  getSealedEnvPubKey(request: VmmTypes.IAppId): Promise<VmmTypes.ISealedEnvPubKeyResponse>;
  getAppEnvEncryptPubKey(request: VmmTypes.IAppId): Promise<VmmTypes.IPublicKeyResponse>;
};

/** allowed_envs for `envs`, in their order: `NAME: spec` for a variable with a value spec, the plain name otherwise. */
export function allowedEnvsOf(envs: EnvEntry[]): string[] {
  const covered = new Set(envs.filter((env) => env.spec?.trim()).map((env) => env.key));
  const entries = envs.flatMap((env) => {
    if (env.spec?.trim()) return [`${env.key}: ${env.spec.trim()}`];
    return covered.has(env.key) ? [] : [env.key];
  });
  return [...new Set(entries)];
}

/** `envs` replaced by `KEY=VALUE` lines. Variables with a value spec stay, without a value if no line names them. */
export function replaceEnvs(envs: EnvEntry[], content: string): EnvEntry[] {
  const lines = content.split('\n').map((line) => line.trim())
    .filter((line) => !line.startsWith('#') && line.indexOf('=') > 0)
    .map((line) => ({ key: line.slice(0, line.indexOf('=')).trim(), value: line.slice(line.indexOf('=') + 1).trim() }))
    .filter((line) => line.key);
  const withSpec = envs.filter((env) => env.spec?.trim());
  const named = new Set(lines.map((line) => line.key));
  return [
    ...lines.flatMap((line) => {
      const rows = withSpec.filter((env) => env.key === line.key);
      return rows.length ? rows.map((env) => ({ ...env, value: line.value })) : [line];
    }),
    ...withSpec.filter((env) => !named.has(env.key)).map((env) => ({ ...env, value: '' })),
  ];
}

/** The `NAME: spec` entries of `allowedEnvs` as variables without a value, to edit or remove. */
export function specEntries(allowedEnvs: string[]): EnvEntry[] {
  return allowedEnvs.filter((entry) => entry.includes(':')).map((entry) => {
    const at = entry.indexOf(':');
    return { key: entry.slice(0, at), value: '', spec: entry.slice(at + 1).trim() };
  });
}

/** Keep key retrieval on the authenticated, same-origin VMM transport. */
export async function encryptEnvPayload(
  client: KeyClient,
  envs: EnvEntry[],
  appId: Uint8Array,
  encryptLegacy: (envs: EnvEntry[], key: Uint8Array) => Promise<Uint8Array>,
  supportsSealedEnv: boolean,
): Promise<EnvPayload> {
  envs = envs.map(({ key, value }) => ({ key, value }));
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
