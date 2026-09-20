// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

const net = require('net')
const { DstackClientV1, DstackClientV0 } = require(require('path').join(__dirname, '..', '..', 'js', 'dist', 'index.js'))

const [sock, name, method] = process.argv.slice(2)

function select() {
  return new Promise((res, rej) => {
    const c = net.connect(sock, () => {
      c.write(`POST /__case/${name} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n`)
    })
    c.on('data', () => { c.end(); res() })
    c.on('error', rej)
  })
}

const t = f => { try { return f() } catch (e) { return '<'+e.constructor.name+'>' } }
const hexClip = (u8, n) => Buffer.from(u8).toString('hex').slice(0, n)

;(async () => {
  await select()
  const c = method.startsWith('v0') ? new DstackClientV0(sock) : new DstackClientV1(sock)
  try {
    let out
    if (method === 'GetKey') {
      const r = await c.getKey('d', 'secp256k1')
      out = `key=${hexClip(r.key,16)} chain=${r.signature_chain.length}`
    } else if (method === 'Info') {
      const r = await c.info()
      out = `app_id=${hexClip(r.app_id,16)} app_name=${JSON.stringify(r.app_name)} os_image_hash=${hexClip(r.os_image_hash,16)}`
    } else if (method === 'v0GetKey') {
      const r = await c.getKey('d')
      out = `key=${hexClip(r.key,16)} keylen=${r.key.length} chain=${r.signature_chain.length}`
    } else if (method === 'v0Info') {
      const r = await c.info()
      out = `app_id=${String(r.app_id).slice(0,16)} tcb=${typeof r.tcb_info}`
    } else if (method === 'v0TlsKey') {
      const r = await c.getTlsKey()
      out = `as32=${t(()=>hexClip(r.asUint8Array(32),64))} full=${t(()=>String(r.asUint8Array().length))}`
    } else if (method === 'Attest') {
      const r = await c.attest(Buffer.alloc(32, 1), false)
      out = `attestation=${r.attestation.length}B gpu=${r.boottime_gpu_evidence.length}`
    }
    // prototype pollution probe
    const polluted = ({}).polluted !== undefined ? ' [PROTO-POLLUTED]' : ''
    console.log(`OK|${out}${polluted}`)
  } catch (e) {
    console.log(`ERR|${e.constructor.name}: ${String(e.message).replace(/\n/g,' ').slice(0,160)}`)
  }
})().catch(e => console.log(`ERR|fatal ${e}`))
