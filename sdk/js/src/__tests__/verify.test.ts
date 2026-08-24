// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Drives the shared cross-SDK vectors in `sdk/tests/vectors/signature_chain.json`.
// The Rust, Python and Go suites assert against the same file, so any port that
// disagrees about the byte format fails here too.

import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { secp256k1 } from '@noble/curves/secp256k1'
import { expect, describe, it } from 'vitest'
import { verifySignature, verifySignatureChain, SIGN_PURPOSE } from '../verify'

interface Case {
  algorithm: string
  data: string
  public_key: string
  signature: string
  signature_chain: string[]
}

interface InvalidCase {
  name: string
  reason: string
  algorithm: string
  data: string
  public_key: string
  signature: string
}

interface Vectors {
  app_id: string
  purpose: string
  path: string
  kms_root_pubkey: string
  app_root_pubkey: string
  wrong_kms_root_pubkey: string
  cases: Case[]
  invalid_cases: InvalidCase[]
}

const vectors: Vectors = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL('../../../tests/vectors/signature_chain.json', import.meta.url),
    ),
    'utf8',
  ),
)

function unhex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'))
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex')
}

function caseFor(algorithm: string): Case {
  const found = vectors.cases.find((c) => c.algorithm === algorithm)
  if (!found) throw new Error(`no vector for ${algorithm}`)
  return found
}

function chainOf(testCase: Case) {
  return {
    algorithm: testCase.algorithm,
    data: unhex(testCase.data),
    publicKey: unhex(testCase.public_key),
    signatureChain: testCase.signature_chain.map(unhex),
    appId: unhex(vectors.app_id),
    kmsRootPubKey: unhex(vectors.kms_root_pubkey),
  }
}

describe('verifySignature', () => {
  it('accepts every valid vector', () => {
    expect(vectors.cases.length).toBeGreaterThan(0)
    for (const c of vectors.cases) {
      expect(
        verifySignature(
          c.algorithm,
          unhex(c.data),
          unhex(c.signature),
          unhex(c.public_key),
        ),
        `${c.algorithm}: valid signature was rejected`,
      ).toBe(true)
    }
  })

  it('rejects every invalid vector', () => {
    expect(vectors.invalid_cases.length).toBeGreaterThan(0)
    for (const c of vectors.invalid_cases) {
      const verify = () =>
        verifySignature(
          c.algorithm,
          unhex(c.data),
          unhex(c.signature),
          unhex(c.public_key),
        )
      if (c.name === 'secp256k1_high_s') {
        // High-S is refused outright rather than reported false, because it is a
        // malformed encoding rather than a legitimate signature that fails to match.
        expect(verify, c.name).toThrow(/high-S/)
      } else {
        expect(verify(), `${c.name}: should not have verified`).toBe(false)
      }
    }
  })

  it('treats k256 as an alias for secp256k1', () => {
    const c = caseFor('secp256k1')
    expect(
      verifySignature(
        'k256',
        unhex(c.data),
        unhex(c.signature),
        unhex(c.public_key),
      ),
    ).toBe(true)
  })

  it('accepts an uncompressed SEC1 public key', () => {
    const c = caseFor('secp256k1')
    // 0x03-prefixed compressed key from the vectors, expanded to 65 bytes.
    const compressed = unhex(c.public_key)
    expect(compressed.length).toBe(33)
    const uncompressed = secp256k1.ProjectivePoint.fromHex(compressed).toRawBytes(false)
    expect(uncompressed.length).toBe(65)
    expect(
      verifySignature(
        c.algorithm,
        unhex(c.data),
        unhex(c.signature),
        uncompressed,
      ),
    ).toBe(true)
  })

  it('throws on malformed inputs rather than reporting false', () => {
    expect(() =>
      verifySignature('rsa', new Uint8Array([1]), new Uint8Array(64), new Uint8Array(32)),
    ).toThrow(/unsupported algorithm/)
    expect(() =>
      verifySignature('ed25519', new Uint8Array([1]), new Uint8Array(64), new Uint8Array(31)),
    ).toThrow(/32 bytes/)
    expect(() =>
      verifySignature('ed25519', new Uint8Array([1]), new Uint8Array(63), new Uint8Array(32)),
    ).toThrow(/64 bytes/)

    // A prehashed digest must be exactly 32 bytes.
    const prehashed = caseFor('secp256k1_prehashed')
    expect(() =>
      verifySignature(
        'secp256k1_prehashed',
        new TextEncoder().encode('short'),
        unhex(prehashed.signature),
        unhex(prehashed.public_key),
      ),
    ).toThrow(/32-byte digest/)

    // Raw 64-byte r || s only; DER is not accepted.
    const secp = caseFor('secp256k1')
    expect(() =>
      verifySignature(
        'secp256k1',
        unhex(secp.data),
        unhex(secp.signature).slice(0, 63),
        unhex(secp.public_key),
      ),
    ).toThrow(/64 raw bytes/)
    expect(() =>
      verifySignature(
        'secp256k1',
        unhex(secp.data),
        unhex(secp.signature),
        unhex(secp.public_key).slice(0, 32),
      ),
    ).toThrow(/public key/)
  })
})

describe('verifySignatureChain', () => {
  it('verifies every vector up to the KMS root', () => {
    for (const c of vectors.cases) {
      const appRoot = verifySignatureChain(chainOf(c))
      expect(appRoot.length).toBe(33)
      expect(hex(appRoot), `${c.algorithm}: recovered the wrong app root key`).toBe(
        vectors.app_root_pubkey,
      )
    }
  })

  it('defaults purpose to the agent-side signing constant', () => {
    expect(SIGN_PURPOSE).toBe('signing')
    expect(vectors.purpose).toBe(SIGN_PURPOSE)
    const c = vectors.cases[0]
    expect(hex(verifySignatureChain({ ...chainOf(c), purpose: SIGN_PURPOSE }))).toBe(
      vectors.app_root_pubkey,
    )
  })

  it('rejects a chain anchored at a foreign KMS root', () => {
    const c = vectors.cases[0]
    expect(() =>
      verifySignatureChain({
        ...chainOf(c),
        kmsRootPubKey: unhex(vectors.wrong_kms_root_pubkey),
      }),
    ).toThrow(/not anchored/)
  })

  it('rejects a chain issued for a different app id', () => {
    const c = vectors.cases[0]
    const appId = unhex(vectors.app_id)
    appId[0] ^= 0xff
    expect(() => verifySignatureChain({ ...chainOf(c), appId })).toThrow()
  })

  it('rejects a tampered payload', () => {
    const c = vectors.cases[0]
    expect(() =>
      verifySignatureChain({
        ...chainOf(c),
        data: new TextEncoder().encode('a different payload entirely'),
      }),
    ).toThrow()
  })

  it('rejects a tampered purpose', () => {
    const c = vectors.cases[0]
    expect(() =>
      verifySignatureChain({ ...chainOf(c), purpose: 'encryption' }),
    ).toThrow(/not anchored/)
  })

  it('rejects malformed chain shapes', () => {
    const c = vectors.cases[0]
    expect(() =>
      verifySignatureChain({
        ...chainOf(c),
        signatureChain: c.signature_chain.slice(0, 2).map(unhex),
      }),
    ).toThrow(/3 elements/)
    expect(() =>
      verifySignatureChain({ ...chainOf(c), appId: unhex(vectors.app_id).slice(0, 19) }),
    ).toThrow(/20 bytes/)
  })
})
