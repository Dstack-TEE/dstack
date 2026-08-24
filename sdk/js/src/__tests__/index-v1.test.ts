// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { expect, describe, it } from 'vitest'
import http from 'http'
import type { AddressInfo } from 'net'
import { DstackClientV0, DstackClientV1 } from '../index'
import type { GpuEvidenceBundleV1 } from '../index'

describe('DstackClientV1', () => {
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

    it('should expose the key as a uint8array of the requested length', async () => {
      const client = new DstackClientV1()
      const result = await client.issueCert()
      const full = result.asUint8Array()
      const truncated = result.asUint8Array(32)
      expect(full).toBeInstanceOf(Uint8Array)
      expect(truncated.length).toBe(32)
      expect(truncated.length).not.toBe(full.length)
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
      const result = await client.getKey('wallet', 'secp256k1')
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
      const result = await client.getKey('wallet', 'ed25519')
      expect(result.key.length).toBe(32)
      expect(result.public_key.length).toBe(32)
      expect(result.signature_chain.length).toBe(2)
    })

    it('should be deterministic for the same domain and algorithm', async () => {
      const client = new DstackClientV1()
      const first = await client.getKey('wallet', 'secp256k1')
      const second = await client.getKey('wallet', 'secp256k1')
      expect(first.key).toEqual(second.key)
    })

    it('should separate the two curves, which v0 did not', async () => {
      const client = new DstackClientV1()
      const secp = await client.getKey('wallet', 'secp256k1')
      const ed = await client.getKey('wallet', 'ed25519')
      expect(secp.key).not.toEqual(ed.key)
    })

    it('should derive different material than v0 for the same name', async () => {
      const v0 = await new DstackClientV0().getKey('wallet', '', 'secp256k1')
      const v1 = await new DstackClientV1().getKey('wallet', 'secp256k1')
      expect(v1.key).not.toEqual(v0.key)
    })

    it('should treat the domain as flat rather than a path', async () => {
      const client = new DstackClientV1()
      const parent = await client.getKey('a', 'secp256k1')
      const child = await client.getKey('a/b', 'secp256k1')
      expect(parent.key).not.toEqual(child.key)
    })

    it('should accept an empty domain', async () => {
      const client = new DstackClientV1()
      const result = await client.getKey('', 'secp256k1')
      expect(result.key.length).toBe(32)
    })

    it('should reject an empty algorithm without a round trip', async () => {
      const client = new DstackClientV1()
      await expect(() => client.getKey('wallet', '')).rejects.toThrow('algorithm is required')
    })

    it('should reject the v0 k256 alias', async () => {
      const client = new DstackClientV1()
      await expect(() => client.getKey('wallet', 'k256')).rejects.toThrow()
    })

    it('should reject secp256k1_prehashed, which named a signing mode', async () => {
      const client = new DstackClientV1()
      await expect(() => client.getKey('wallet', 'secp256k1_prehashed')).rejects.toThrow()
    })
  })

  describe('attest', () => {
    it('should attest over report data', async () => {
      const client = new DstackClientV1()
      const result = await client.attest('test')
      expect(result.attestation).not.toBe('')
      expect(result.boottime_gpu_evidence).toEqual([])
    })

    it('should accept the boot-time GPU evidence flag', async () => {
      const client = new DstackClientV1()
      const result = await client.attest('test', true)
      expect(result.attestation).not.toBe('')
      // Absence is the empty list, not a sentinel; the simulator has no GPU
      // output, so this is empty here but must still be an array.
      expect(Array.isArray(result.boottime_gpu_evidence)).toBe(true)
      expect(result.boottime_gpu_evidence).toEqual([])
    })

    it('should type boot-time evidence as the bundle list attestGpu returns', async () => {
      const client = new DstackClientV1()
      const result = await client.attest('test', true)
      // Assigning one to the other is the assertion: one parser, both methods.
      const bundles: GpuEvidenceBundleV1[] = result.boottime_gpu_evidence
      for (const bundle of bundles) {
        expect(bundle.asUint8Array()).toBeInstanceOf(Uint8Array)
      }
    })

    it('should reject report data outside 1..64 bytes', async () => {
      const client = new DstackClientV1()
      await expect(() => client.attest('')).rejects.toThrow('must not be empty')
      await expect(() => client.attest(Buffer.alloc(65))).rejects.toThrow('at most 64 bytes')
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
      // rather than hang for the attestation timeout.
      await expect(() => client.attestGpu(new Uint8Array(32).fill(0xab))).rejects.toThrow(
        'GPU attestation'
      )
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
      expect(result.app_id).not.toBe('')
      expect(result.instance_id).not.toBe('')
    })

    it('should not nest measurements in a tcb_info blob or mint an app_cert', async () => {
      const client = new DstackClientV1()
      const result = await client.info() as any
      expect(result.tcb_info).toBeUndefined()
      expect(result.app_cert).toBeUndefined()
    })

    it('should hex-encode the byte fields', async () => {
      const client = new DstackClientV1()
      const result = await client.info()
      expect(result.app_id).toMatch(/^[0-9a-f]+$/)
      expect(result.compose_hash).toMatch(/^[0-9a-f]{64}$/)
      expect(result.mr_aggregated).toMatch(/^[0-9a-f]{64}$/)
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
