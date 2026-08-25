// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { expect, describe, it } from 'vitest'
import http from 'http'
import type { AddressInfo } from 'net'
import { DstackClient, DstackClientV0, DstackClientV1 } from '../index'
import type { GpuEvidenceBundleV1 } from '../index'

describe('DstackClientV1', () => {
  it('should be what the unsuffixed DstackClient names, as value and as type', () => {
    expect(DstackClient).toBe(DstackClientV1)
    // Typed as the alias, constructed through the alias: this line fails to
    // compile if either half of the export stops pointing at v1.
    const client: DstackClient = new DstackClient()
    expect(client).toBeInstanceOf(DstackClientV1)
    expect(client).not.toBeInstanceOf(DstackClientV0)
  })

  it('should be able to get version', async () => {
    const client = new DstackClientV1()
    const result = await client.version()
    expect(result).toHaveProperty('version')
    expect(result).toHaveProperty('rev')
    expect(result.version).not.toBe('')
  })

  describe('issueCert', () => {
    it('should issue a certificate with a fresh key', async () => {
      const client = new DstackClientV1()
      const result = await client.issueCert({
        subject: 'test-subject',
        altNames: ['localhost', '127.0.0.1'],
        usageRaTls: true,
        usageServerAuth: true,
        usageClientAuth: true,
      })
      expect(result.key).toContain('-----BEGIN PRIVATE KEY-----')
      expect(result.certificate_chain.length).toBeGreaterThan(0)
      expect(result.certificate_chain[0]).toContain('-----BEGIN CERTIFICATE-----')
    })

    it('should generate an unrelated key on every call', async () => {
      const client = new DstackClientV1()
      const first = await client.issueCert({ subject: 'test-subject' })
      const second = await client.issueCert({ subject: 'test-subject' })
      expect(first.key).not.toBe(second.key)
    })

    it('should hand back the key as PEM and nothing else', async () => {
      const client = new DstackClientV1()
      const result = await client.issueCert() as any
      // The raw-bytes accessor v0 carries fed the chain adapters, and v1 has no
      // chain surface. All four SDKs return the PEM string alone here.
      expect(result.asUint8Array).toBeUndefined()
      expect(Object.keys(result).sort()).toEqual(['__name__', 'certificate_chain', 'key'])
    })

    it('should reject a validity window that ends before it starts', async () => {
      const client = new DstackClientV1()
      const now = Math.floor(Date.now() / 1000)
      await expect(() => client.issueCert({ notBefore: now + 3600, notAfter: now })).rejects.toThrow()
    })
  })

  describe('getKey', () => {
    it('should derive a secp256k1 key with a public key and a two-link chain', async () => {
      const client = new DstackClientV1()
      const result = await client.getKey('storage-encryption', 'secp256k1')
      expect(result.key).toBeInstanceOf(Uint8Array)
      expect(result.key.length).toBe(32)
      // SEC1 compressed, so the chain's first link commits to these exact bytes.
      expect(result.public_key.length).toBe(33)
      expect([0x02, 0x03]).toContain(result.public_key[0])
      expect(result.signature_chain.length).toBe(2)
      for (const link of result.signature_chain) {
        expect(link).toBeInstanceOf(Uint8Array)
        expect(link.length).toBe(65) // recoverable r || s || v
      }
    })

    it('should derive an ed25519 key with a 32-byte public key', async () => {
      const client = new DstackClientV1()
      const result = await client.getKey('storage-encryption', 'ed25519')
      expect(result.key.length).toBe(32)
      expect(result.public_key.length).toBe(32)
      expect(result.signature_chain.length).toBe(2)
    })

    it('should be deterministic for the same domain and algorithm', async () => {
      const client = new DstackClientV1()
      const first = await client.getKey('storage-encryption', 'secp256k1')
      const second = await client.getKey('storage-encryption', 'secp256k1')
      expect(first.key).toEqual(second.key)
    })

    it('should separate the two curves, which v0 did not', async () => {
      const client = new DstackClientV1()
      const secp = await client.getKey('storage-encryption', 'secp256k1')
      const ed = await client.getKey('storage-encryption', 'ed25519')
      expect(secp.key).not.toEqual(ed.key)
    })

    it('should derive different material than v0 for the same name', async () => {
      const v0 = await new DstackClientV0().getKey('storage-encryption', '', 'secp256k1')
      const v1 = await new DstackClientV1().getKey('storage-encryption', 'secp256k1')
      expect(v1.key).not.toEqual(v0.key)
    })

    it('should treat the domain as flat rather than a path', async () => {
      const client = new DstackClientV1()
      const parent = await client.getKey('a', 'secp256k1')
      const child = await client.getKey('a/b', 'secp256k1')
      expect(parent.key).not.toEqual(child.key)
    })

    // Over the unix socket the SDK writes the HTTP framing itself, and it used
    // to declare `Content-Length` as the string's UTF-16 code-unit count while
    // sending UTF-8 -- so a domain like this one arrived truncated and the
    // surplus bytes were left in the stream. The simulator runs on that path.
    it('should send a domain with multi-byte characters intact', async () => {
      const client = new DstackClientV1()
      const first = await client.getKey('café-storage', 'secp256k1')
      expect(first.key.length).toBe(32)

      // Truncation would land on some prefix of the domain, and derivation binds
      // the domain, so a mangled request cannot derive the same key twice the
      // same way -- nor differ from a genuinely different domain.
      const again = await client.getKey('café-storage', 'secp256k1')
      expect(again.key).toEqual(first.key)
      const truncated = await client.getKey('caf', 'secp256k1')
      expect(truncated.key).not.toEqual(first.key)
    })

    it('should accept an empty domain', async () => {
      const client = new DstackClientV1()
      const result = await client.getKey('', 'secp256k1')
      expect(result.key.length).toBe(32)
    })

    it('should reject an empty algorithm without a round trip', async () => {
      const client = new DstackClientV1()
      await expect(() => client.getKey('storage-encryption', '')).rejects.toThrow('algorithm is required')
    })

    it('should reject the v0 k256 alias', async () => {
      const client = new DstackClientV1()
      await expect(() => client.getKey('storage-encryption', 'k256')).rejects.toThrow()
    })

    it('should reject secp256k1_prehashed, which named a signing mode', async () => {
      const client = new DstackClientV1()
      await expect(() => client.getKey('storage-encryption', 'secp256k1_prehashed')).rejects.toThrow()
    })
  })

  describe('attest', () => {
    it('should attest over report data', async () => {
      const client = new DstackClientV1()
      const result = await client.attest(Buffer.from('test'))
      expect(result.attestation).toBeInstanceOf(Uint8Array)
      expect(result.attestation.length).toBeGreaterThan(0)
      expect(result.boottime_gpu_evidence).toEqual([])
    })

    it('should accept the boot-time GPU evidence flag', async () => {
      const client = new DstackClientV1()
      const result = await client.attest(Buffer.from('test'), true)
      expect(result.attestation.length).toBeGreaterThan(0)
      // Absence is the empty list, not a sentinel; the simulator has no GPU
      // output, so this is empty here but must still be an array.
      expect(Array.isArray(result.boottime_gpu_evidence)).toBe(true)
      expect(result.boottime_gpu_evidence).toEqual([])
    })

    it('should type boot-time evidence as the bundle list attestGpu returns', async () => {
      const client = new DstackClientV1()
      const result = await client.attest(Buffer.from('test'), true)
      // Assigning one to the other is the assertion: one parser, both methods.
      const bundles: GpuEvidenceBundleV1[] = result.boottime_gpu_evidence
      for (const bundle of bundles) {
        expect(bundle.evidence).toBeInstanceOf(Uint8Array)
      }
    })

    it('should reject report data outside 1..64 bytes', async () => {
      const client = new DstackClientV1()
      await expect(() => client.attest(new Uint8Array(0))).rejects.toThrow('must not be empty')
      await expect(() => client.attest(Buffer.alloc(65))).rejects.toThrow('at most 64 bytes')
    })

    it('should reject a string rather than attest its characters', async () => {
      const client = new DstackClientV1()
      // v0 UTF-8 encoded this. `attest('deadbeef')` then committed to eight
      // ASCII characters rather than the four bytes they spell, silently.
      await expect(
        () => (client as unknown as {
          attest: (d: unknown) => Promise<unknown>
        }).attest('deadbeef')
      ).rejects.toThrow(/report data must be bytes, not a string/)
    })

    it('should reject a 32-character string nonce that would pass the length check', async () => {
      const client = new DstackClientV1()
      await expect(
        () => (client as unknown as {
          attestGpu: (n: unknown) => Promise<unknown>
        }).attestGpu('a'.repeat(32))
      ).rejects.toThrow(/nonce must be bytes, not a string/)
    })
  })

  describe('attestGpu', () => {
    it('should reject a nonce that is not exactly 32 bytes', async () => {
      const client = new DstackClientV1()
      await expect(() => client.attestGpu(new Uint8Array(31))).rejects.toThrow('exactly 32 bytes')
      await expect(() => client.attestGpu(new Uint8Array(33))).rejects.toThrow('exactly 32 bytes')
    })

    it('should surface the agent failure when there is no GPU', async () => {
      const client = new DstackClientV1()
      // The simulator ships no nvattest, so this must fail fast and clearly
      // rather than hang for the attestation timeout -- with the status the
      // agent answered and its own explanation, not a parse error.
      //
      // 501 specifically, not any 4xx: the agent distinguishes "this image can
      // never attest a GPU" from "your request was wrong", and a client that
      // cannot see the difference retries a call that will never succeed.
      await expect(() => client.attestGpu(new Uint8Array(32).fill(0xab))).rejects.toThrow(
        /^HTTP 501: .*GPU attestation is not available/
      )
    })
  })

  describe('GPU evidence bundles', () => {
    // The simulator ships no nvattest, so a stub agent is the only way to see a
    // non-empty bundle -- and the decoding is what a verifier depends on.
    const nvattest_output = '{"nonce": "00", "measurements": []}\n'
    const evidence = Buffer.from(nvattest_output, 'utf8').toString('hex')

    async function withStubAgent(fn: (client: DstackClientV1) => Promise<void>) {
      const server = http.createServer((req, res) => {
        const body = req.url === '/v1/Attest'
          ? {
            attestation: 'aabb',
            boottime_gpu_evidence: [
              { vendor: 'nvidia', format: 'nvidia-nvattest-boottime-json-v1', evidence },
            ],
          }
          : {
            bundles: [
              { vendor: 'nvidia', format: 'nvidia-nvattest-collect-evidence-json-v1', evidence },
            ],
          }
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(body))
      })
      await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
      try {
        const { port } = server.address() as AddressInfo
        await fn(new DstackClientV1(`http://127.0.0.1:${port}`))
      } finally {
        await new Promise<void>(resolve => server.close(() => resolve()))
      }
    }

    it('should decode boot-time evidence to the nvattest bytes verbatim', async () => {
      await withStubAgent(async client => {
        const result = await client.attest(Buffer.from('test'), true)
        const [bundle] = result.boottime_gpu_evidence
        expect(bundle.vendor).toBe('nvidia')
        expect(bundle.format).toBe('nvidia-nvattest-boottime-json-v1')
        // Byte-exact: sha256 over these bytes is what `evidence_sha256` in the
        // measured `gpu-attestation` event commits to.
        expect(Buffer.from(bundle.evidence).toString('utf8')).toBe(nvattest_output)
      })
    })

    it('should hand both methods the same bundle shape', async () => {
      await withStubAgent(async client => {
        const attested = await client.attest(Buffer.from('test'), true)
        const collected = await client.attestGpu(new Uint8Array(32))
        const boottime: GpuEvidenceBundleV1 = attested.boottime_gpu_evidence[0]
        const on_demand: GpuEvidenceBundleV1 = collected.bundles[0]
        // Only `format` separates them, so one parser handles both.
        expect(on_demand.format).toBe('nvidia-nvattest-collect-evidence-json-v1')
        expect(on_demand.evidence).toEqual(boottime.evidence)
      })
    })
  })

  // Every one of these decoded to a shorter-than-asked-for Uint8Array with no
  // error before the hex decoding was made strict: Node's decoder stops at the
  // first pair it cannot parse and returns the prefix. A truncated `key` or a
  // signature chain quietly one link short is a verification failure nobody can
  // trace back to its cause.
  describe('malformed hex from the agent', () => {
    async function withAgentAnswering(body: unknown, fn: (client: DstackClientV1) => Promise<void>) {
      const server = http.createServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(body))
      })
      await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
      try {
        const { port } = server.address() as AddressInfo
        await fn(new DstackClientV1(`http://127.0.0.1:${port}`))
      } finally {
        await new Promise<void>(resolve => server.close(() => resolve()))
      }
    }

    const identity = {
      app_id: 'aa'.repeat(20),
      compose_hash: 'bb'.repeat(32),
      instance_id: 'cc'.repeat(20),
      device_id: 'dd'.repeat(32),
      os_image_hash: 'ee'.repeat(32),
      mr_aggregated: 'ff'.repeat(48),
    }

    it('should reject a non-hex character rather than truncate', async () => {
      await withAgentAnswering({ ...identity, app_id: 'aabbzz' + 'aa'.repeat(17) }, client =>
        expect(client.info()).rejects.toThrow(/malformed app_id/)
      )
    })

    it('should reject an odd-length string rather than drop a digit', async () => {
      await withAgentAnswering({ ...identity, compose_hash: 'abc' }, client =>
        expect(client.info()).rejects.toThrow(/malformed compose_hash/)
      )
    })

    it('should name the chain link that is malformed', async () => {
      await withAgentAnswering(
        { key: 'aa'.repeat(32), public_key: 'bb'.repeat(33), signature_chain: ['aabb', 'qq'] },
        client => expect(client.getKey('x', 'secp256k1')).rejects.toThrow(/signature_chain\[1\]/)
      )
    })

    it('should reject an absent required field instead of returning empty bytes', async () => {
      const { instance_id: _dropped, ...without_instance_id } = identity
      await withAgentAnswering(without_instance_id, client =>
        expect(client.info()).rejects.toThrow(/no instance_id/)
      )
    })

    it('should accept an absent optional field as empty', async () => {
      const { os_image_hash: _a, mr_aggregated: _b, ...older_agent } = identity
      await withAgentAnswering(older_agent, async client => {
        const info = await client.info()
        expect(info.os_image_hash).toEqual(new Uint8Array(0))
        expect(info.mr_aggregated).toEqual(new Uint8Array(0))
        expect(info.app_id.length).toBe(20)
      })
    })

    // A hex check alone does not survive a value that is not a string:
    // `RegExp.test` stringifies, so `['00112233']` passes it, and `Buffer.from`
    // then coerces the element as an octet and yields one attacker-chosen byte
    // without erroring. These pin the type check that stops it.
    it('should reject a one-element array rather than coerce it to a byte', async () => {
      await withAgentAnswering({ ...identity, app_id: ['00112233'] }, client =>
        expect(client.info()).rejects.toThrow(/malformed app_id.*got an array/)
      )
    })

    it('should reject a chain link that is an array rather than a string', async () => {
      await withAgentAnswering(
        { key: 'aa'.repeat(32), public_key: 'bb'.repeat(33), signature_chain: [['61']] },
        client => expect(client.getKey('x', 'secp256k1')).rejects.toThrow(
          /malformed signature_chain\[0\].*got an array/)
      )
    })

    it('should reject a null field rather than read it as empty bytes', async () => {
      await withAgentAnswering({ ...identity, os_image_hash: null }, client =>
        expect(client.info()).rejects.toThrow(/malformed os_image_hash.*got null/)
      )
    })

    it('should name the field when a repeated one is not a list', async () => {
      await withAgentAnswering(
        { key: 'aa'.repeat(32), public_key: 'bb'.repeat(33), signature_chain: null },
        client => expect(client.getKey('x', 'secp256k1')).rejects.toThrow(
          /malformed signature_chain: expected a list/)
      )
    })

    it('should reject an absent bundles rather than report no GPUs', async () => {
      await withAgentAnswering({}, client =>
        expect(client.attestGpu(new Uint8Array(32))).rejects.toThrow(
          /malformed bundles: expected a list/)
      )
    })

    it('should reject a bundle without the vendor a caller dispatches on', async () => {
      await withAgentAnswering(
        { bundles: [{ format: 'nvidia-nvattest-collect-evidence-json-v1', evidence: 'aa' }] },
        client => expect(client.attestGpu(new Uint8Array(32))).rejects.toThrow(
          /malformed bundles\[0\]\.vendor.*got nothing/)
      )
    })

    it('should read an absent string field as empty, not undefined', async () => {
      await withAgentAnswering(identity, async client => {
        const info = await client.info()
        expect(info.app_compose).toBe('')
        expect(info.cloud_vendor).toBe('')
        expect(info.app_name).toBe('')
      })
    })
  })

  describe('info', () => {
    it('should return the flat identity shape', async () => {
      const client = new DstackClientV1()
      const result = await client.info()
      for (const field of [
        'app_id', 'app_name', 'compose_hash', 'app_compose', 'instance_id', 'device_id',
        'os_image_hash', 'mr_aggregated', 'vm_config', 'key_provider_info',
        'cloud_vendor', 'cloud_product',
      ]) {
        expect(result).toHaveProperty(field)
      }
      expect(result.app_id.length).toBeGreaterThan(0)
      expect(result.instance_id.length).toBeGreaterThan(0)
    })

    it('should not nest measurements in a tcb_info blob or mint an app_cert', async () => {
      const client = new DstackClientV1()
      const result = await client.info() as any
      expect(result.tcb_info).toBeUndefined()
      expect(result.app_cert).toBeUndefined()
    })

    it('should decode the byte fields rather than hand back hex', async () => {
      const client = new DstackClientV1()
      const result = await client.info()
      // The proto says `bytes`, so the SDK says `Uint8Array`: a caller that
      // hashes or compares an identity gets the 20 or 32 bytes it means, not
      // the 40 or 64 ASCII characters the wire carries.
      expect(result.app_id).toBeInstanceOf(Uint8Array)
      expect(result.app_id.length).toBe(20)
      expect(result.compose_hash.length).toBe(32)
      expect(result.instance_id.length).toBe(20)
      expect(result.device_id.length).toBe(32)
      expect(result.mr_aggregated.length).toBe(32)
    })

    it('should serve app_compose verbatim rather than nested in another JSON string', async () => {
      const client = new DstackClientV1()
      const result = await client.info()
      // Handed over as the deployed bytes, so a caller can hash them directly.
      // v0 reached this through a JSON string inside `tcb_info`.
      expect(typeof result.app_compose).toBe('string')
      expect(() => JSON.parse(result.app_compose)).not.toThrow()
      expect(JSON.parse(result.app_compose)).toHaveProperty('manifest_version')
    })
  })

  it('should serve only the six v1 methods', () => {
    const client = new DstackClientV1() as any
    for (const absent of ['sign', 'verify', 'emitEvent', 'getQuote', 'gpuInfo', 'getTlsKey']) {
      expect(client[absent]).toBeUndefined()
    }
  })

  it('should throw when the unix socket file does not exist', () => {
    const savedEnv = process.env.DSTACK_SIMULATOR_ENDPOINT
    delete process.env.DSTACK_SIMULATOR_ENDPOINT

    expect(() => new DstackClientV1('/non/existent/socket')).toThrow(
      'Unix socket file /non/existent/socket does not exist'
    )
    expect(() => new DstackClientV1('http://localhost:8080')).not.toThrow()

    if (savedEnv) {
      process.env.DSTACK_SIMULATOR_ENDPOINT = savedEnv
    }
  })
})
