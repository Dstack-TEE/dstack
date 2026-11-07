// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const { webcrypto } = require('node:crypto');
const { CipherSuite, Aes256Gcm, HkdfSha256 } = require('@hpke/core');
const { DhkemX25519HkdfSha256 } = require('@hpke/dhkem-x25519');
const { encryptEnvPayload } = require('../build/ts/lib/envEncryption.js');
const { RpcError } = require('../build/ts/lib/vmmRpcClient.js');
const { vmm } = require('../build/ts/proto/vmm_rpc.js');
const { prpc } = require('../build/ts/proto/prpc.js');

const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
const appId = new Uint8Array(20).fill(0x11);
const envs = [{ key: 'GREETING', value: 'Hello 世界' }];
const missing = 'Service not found: GetSealedEnvPubKey';

async function recipient() {
  const pair = await suite.kem.generateKeyPair();
  const public_key = new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  return { pair, response: { public_key, root_epoch: 7, timestamp: 123, signature: new Uint8Array(65) } };
}

async function open(pair, bytes, epoch) {
  const envelope = JSON.parse(new TextDecoder().decode(bytes));
  assert.equal(envelope.version, 1);
  const pt = await suite.open({
    recipientKey: pair.privateKey,
    enc: Buffer.from(envelope.enc, 'base64'),
    info: new TextEncoder().encode(`dstack-sealed-env-v1:${epoch ?? envelope.root_epoch}`),
  }, Buffer.from(envelope.ciphertext, 'base64'));
  return JSON.parse(new TextDecoder().decode(pt));
}

const noLegacy = async () => { throw new Error('unexpected legacy fallback'); };

test('seals JSON bytes with HPKE, binds epoch, and rejects tampering', async () => {
  const { pair, response } = await recipient();
  for (const epoch of [0, 7, 0xffffffff]) {
    const payload = await encryptEnvPayload({
      getSealedEnvPubKey: async (request) => {
        assert.deepEqual(request, { app_id: appId });
        return { ...response, root_epoch: epoch };
      },
      getAppEnvEncryptPubKey: noLegacy,
    }, envs, appId, noLegacy);
    assert.deepEqual(Object.keys(payload), ['sealed_env']);
    assert.deepEqual(await open(pair, payload.sealed_env), { env: envs });
    await assert.rejects(open(pair, payload.sealed_env, epoch === 0 ? 1 : 0));
    const modified = JSON.parse(new TextDecoder().decode(payload.sealed_env));
    const ct = Buffer.from(modified.ciphertext, 'base64');
    ct[0] ^= 1;
    modified.ciphertext = ct.toString('base64');
    await assert.rejects(open(pair, new TextEncoder().encode(JSON.stringify(modified))));
  }
});

test('falls back only on explicit missing RPC, including a forwarded KMS error', async () => {
  for (const error of [
    new RpcError(missing, 404), new RpcError(missing, 400),
    new RpcError(`Request failed with status=404 Not Found, error=${JSON.stringify({ error: missing })}`, 400),
  ]) {
    let legacyCalls = 0;
    const payload = await encryptEnvPayload({
      getSealedEnvPubKey: async () => { throw error; },
      getAppEnvEncryptPubKey: async (request) => {
        legacyCalls++;
        assert.deepEqual(request, { app_id: appId });
        return { public_key: new Uint8Array(32) };
      },
    }, envs, appId, async (entries, key) => {
      assert.deepEqual(entries, envs);
      assert.equal(key.length, 32);
      return new Uint8Array([1, 2, 3]);
    });
    assert.equal(legacyCalls, 1);
    assert.deepEqual(Object.keys(payload), ['encrypted_env']);
  }
});

test('network, HTTP, authentication and unrelated service errors never downgrade', async () => {
  for (const error of [
    new Error('network failed'), new Error(missing), new RpcError('Not Found', 404),
    new RpcError(missing, 401), new RpcError(missing, 403), new RpcError(missing, 500),
    new RpcError('Service not found: DifferentMethod', 404),
    new RpcError('failed to validate the server attestation', 400),
    new RpcError(`Request failed with status=500 Internal Server Error, error={"error":"${missing}"}`, 400),
  ]) {
    await assert.rejects(encryptEnvPayload({
      getSealedEnvPubKey: async () => { throw error; },
      getAppEnvEncryptPubKey: noLegacy,
    }, envs, appId, noLegacy), (actual) => actual === error);
  }
});

test('invalid key or epoch never downgrades after a successful key RPC', async () => {
  const { response } = await recipient();
  for (const invalid of [
    { public_key: new Uint8Array(31) }, { public_key: new Uint8Array(33) },
    { public_key: new Uint8Array(32) },
    { root_epoch: -1 }, { root_epoch: 1.5 }, { root_epoch: 0x100000000 },
  ]) {
    let legacyCalls = 0;
    await assert.rejects(encryptEnvPayload({
      getSealedEnvPubKey: async () => ({ ...response, ...invalid }),
      getAppEnvEncryptPubKey: async () => { legacyCalls++; return response; },
    }, envs, appId, noLegacy));
    assert.equal(legacyCalls, 0);
  }
});

// Execute the shipped bundle with browser Web Crypto and protobuf transport.
// Vue lifecycle hooks are inert so tests do not start background polling.
function consoleApp(response, unsupported = false) {
  const calls = [];
  const alerts = [];
  let manager;
  const html = readFileSync(new URL('../dist/index.html', `file://${__filename}`), 'utf8');
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  const context = {
    crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer,
    btoa, atob, setTimeout, clearTimeout, console,
    localStorage: { getItem: () => null },
    alert: (message) => alerts.push(message),
    Vue: {
      ref: (value) => ({ value }), computed: (getter) => ({ get value() { return getter(); } }),
      watch: () => {}, onMounted: () => {},
      createApp: (app) => ({ mount: () => { manager = app.setup(); } }),
    },
    fetch: async (url, options) => {
      assert.equal(options.credentials, 'same-origin');
      assert.equal(options.headers['Content-Type'], 'application/octet-stream');
      const method = url.split('/').pop();
      if (method === 'GetSealedEnvPubKey') {
        calls.push({ method, request: vmm.AppId.decode(options.body) });
        if (unsupported) return new Response(prpc.PrpcError.encode({ message: missing }).finish(), { status: 404 });
        return new Response(vmm.SealedEnvPubKeyResponse.encode(response).finish());
      }
      if (method === 'GetAppEnvEncryptPubKey') {
        calls.push({ method });
        return new Response(vmm.PublicKeyResponse.encode({ public_key: response.public_key }).finish());
      }
      if (method === 'CreateVm' || method === 'UpdateVm') {
        const type = method === 'CreateVm' ? vmm.VmConfiguration : vmm.UpdateVmRequest;
        calls.push({ method, request: type.decode(options.body) });
        return new Response(new Uint8Array());
      }
      assert.equal(method, 'Status');
      return new Response(new Uint8Array());
    },
  };
  runInNewContext(scripts.at(-1)[1], context);
  return { manager, calls, alerts };
}

for (const unsupported of [false, true]) {
  test(`browser bundle create and edit use ${unsupported ? 'explicit legacy fallback' : 'sealed_env'}`, async () => {
    const { pair, response } = await recipient();
    const { manager, calls, alerts } = consoleApp(response, unsupported);
    Object.assign(manager.vmForm.value, {
      name: 'test', image: 'test', key_provider: 'kms', encryptedEnvs: envs,
      app_id: '',
    });
    await manager.createVm();
    assert.deepEqual(alerts, []);
    const created = calls.find((call) => call.method === 'CreateVm').request;
    const expectedAppId = new Uint8Array(await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(created.compose_file))).slice(0, 20);
    assert.deepEqual(new Uint8Array(calls[0].request.app_id), expectedAppId);
    Object.assign(manager.updateDialog.value, {
      vm: { id: 'vm', app_id: '11'.repeat(20), configuration: {}, appCompose: { docker_compose_file: '' } },
      resetSecrets: true, encryptedEnvs: [],
    });
    await manager.updateVM();
    assert.deepEqual(alerts, []);
    const edited = calls.find((call) => call.method === 'UpdateVm').request;
    for (const [request, entries] of [[created, envs], [edited, []]]) {
      if (unsupported) {
        assert.ok(request.encrypted_env.length > 44);
        assert.equal(request.sealed_env.length, 0);
      } else {
        assert.equal(request.encrypted_env.length, 0);
        assert.deepEqual(await open(pair, request.sealed_env), { env: entries });
      }
    }
    calls.length = 0;
    manager.updateDialog.value.resetSecrets = false;
    await manager.updateVM();
    assert.equal(calls.some((call) => call.method.startsWith('Get')), false);
    const unchanged = calls.find((call) => call.method === 'UpdateVm').request;
    assert.equal(unchanged.sealed_env.length, 0);
    assert.equal(unchanged.encrypted_env.length, 0);
  });
}


test('create without KMS or without secrets does not request an encryption key', async () => {
  const { response } = await recipient();
  for (const fields of [
    { key_provider: 'none', encryptedEnvs: envs },
    { key_provider: 'kms', encryptedEnvs: [] },
  ]) {
    const { manager, calls, alerts } = consoleApp(response);
    Object.assign(manager.vmForm.value, { name: 'test', image: 'test', ...fields });
    await manager.createVm();
    assert.deepEqual(alerts, []);
    assert.equal(calls.some((call) => call.method.startsWith('Get')), false);
    const created = calls.find((call) => call.method === 'CreateVm').request;
    assert.equal(created.sealed_env.length, 0);
    assert.equal(created.encrypted_env.length, 0);
  }
});
