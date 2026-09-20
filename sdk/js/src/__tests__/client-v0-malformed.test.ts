// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// What the frozen v0 client does with a response the agent could not have sent.
//
// The trust model says the agent is inside the application's TCB, so none of
// these is an attack -- they are a version skew, a broken agent, or an endpoint
// pointed somewhere unintended. What matters is that the failure is *visible*.
// v1 was given this treatment (see `index-v1.test.ts`); v0 never was, and the
// three other SDKs all refuse every response below.

import http from 'http'
import type { AddressInfo } from 'net'
import { describe, expect, it } from 'vitest'
import { DstackClientV0 } from '../client-v0'

async function withAgentAnswering(body: unknown, fn: (client: DstackClientV0) => Promise<void>) {
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(typeof body === 'string' ? body : JSON.stringify(body))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
  try {
    const { port } = server.address() as AddressInfo
    await fn(new DstackClientV0(`http://127.0.0.1:${port}`))
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()))
  }
}

const CHAIN = ['aa'.repeat(64)]

describe('DstackClientV0.getKey with malformed hex', () => {
  // The one that matters. Node's hex decoder stops at the first pair it cannot
  // parse and returns the prefix, with no error -- so 64 good digits followed
  // by junk yields a plausible 32-byte key. `toViemAccount` turns that into a
  // working account at an address nobody chose, and nothing reports a problem.
  // Rust, Python and Go all refuse this identical response.
  it('refuses a key whose valid prefix is exactly the expected length', async () => {
    await withAgentAnswering({ key: '11'.repeat(32) + 'GARBAGE', signature_chain: CHAIN }, async client => {
      await expect(client.getKey('d')).rejects.toThrow(/malformed key/)
    })
  })

  it('refuses a key that is not hex at all', async () => {
    await withAgentAnswering({ key: 'zz'.repeat(32), signature_chain: CHAIN }, async client => {
      await expect(client.getKey('d')).rejects.toThrow(/malformed key/)
    })
  })

  it('refuses an odd-length key rather than dropping the last digit', async () => {
    await withAgentAnswering({ key: '0011222', signature_chain: CHAIN }, async client => {
      await expect(client.getKey('d')).rejects.toThrow(/malformed key/)
    })
  })

  it('refuses a signature chain link that is not hex', async () => {
    await withAgentAnswering({ key: '11'.repeat(32), signature_chain: ['aa', 'zz'] }, async client => {
      await expect(client.getKey('d')).rejects.toThrow(/signature_chain\[1\]/)
    })
  })

  it('still accepts a well-formed response unchanged', async () => {
    await withAgentAnswering({ key: '11'.repeat(32), signature_chain: CHAIN }, async client => {
      const result = await client.getKey('d')
      expect(result.key).toEqual(new Uint8Array(Buffer.from('11'.repeat(32), 'hex')))
      expect(result.signature_chain).toHaveLength(1)
    })
  })

  // An empty hex string is zero bytes everywhere, and stays that way.
  it('still reads an empty key as zero bytes', async () => {
    await withAgentAnswering({ key: '', signature_chain: [] }, async client => {
      const result = await client.getKey('d')
      expect(result.key).toEqual(new Uint8Array(0))
    })
  })
})

describe('DstackClientV0.getKey with a missing field', () => {
  // `Cannot read properties of null (reading 'map')` names no field and reads
  // like an SDK bug rather than a bad response.
  it('names the field when signature_chain is null', async () => {
    await withAgentAnswering({ key: '11'.repeat(32), signature_chain: null }, async client => {
      await expect(client.getKey('d')).rejects.toThrow(/signature_chain/)
    })
  })

  it('names the field when signature_chain is absent', async () => {
    await withAgentAnswering({ key: '11'.repeat(32) }, async client => {
      await expect(client.getKey('d')).rejects.toThrow(/signature_chain/)
    })
  })

  it('names the field when key is absent', async () => {
    await withAgentAnswering({ signature_chain: CHAIN }, async client => {
      await expect(client.getKey('d')).rejects.toThrow(/key/)
    })
  })
})

describe('DstackClientV0.info with a malformed tcb_info', () => {
  const base = {
    app_id: 'aa'.repeat(32),
    instance_id: 'cc'.repeat(32),
    app_cert: 'x',
    app_name: 'demo',
    device_id: 'dd'.repeat(32),
    key_provider_info: '{}',
    compose_hash: 'bb'.repeat(32),
  }
  const tcb = JSON.stringify({
    mrtd: '00'.repeat(48), rtmr0: '00'.repeat(48), rtmr1: '00'.repeat(48),
    rtmr2: '00'.repeat(48), rtmr3: '00'.repeat(48), app_compose: '{}', event_log: [],
  })

  // `JSON.parse(42)` stringifies its argument and succeeds, so `tcb_info` came
  // back as the number 42 typed as `TcbInfo` and every `.mrtd` read was
  // `undefined`. Rust, Python and Go all reject this.
  it('refuses a tcb_info that is not a string', async () => {
    await withAgentAnswering({ ...base, tcb_info: 42 }, async client => {
      await expect(client.info()).rejects.toThrow(/tcb_info/)
    })
  })

  // Previously: `SyntaxError: "undefined" is not valid JSON`.
  it('names the field when tcb_info is absent', async () => {
    await withAgentAnswering(base, async client => {
      await expect(client.info()).rejects.toThrow(/tcb_info/)
    })
  })

  it('still parses a well-formed tcb_info', async () => {
    await withAgentAnswering({ ...base, tcb_info: tcb }, async client => {
      const result = await client.info()
      expect(result.tcb_info.mrtd).toBe('00'.repeat(48))
    })
  })
})
