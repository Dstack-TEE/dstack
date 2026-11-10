// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { wasmBase64 } from '../src/wasm-bytes.js'
import { verifyTdxLiteOs } from '../src/index.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const fixturePath = join(
  root,
  'dstack/verifier/fixtures/tdx-lite-getquote.json',
)

function mrsFromQuoteHex(quoteHex) {
  const quote = Buffer.from(quoteHex, 'hex')
  const version = quote.readUInt16LE(0)
  const header = version === 5 ? 54 : 48
  const field = (offset) => quote.subarray(header + offset, header + offset + 48).toString('hex')
  return {
    mrtd: field(136),
    rtmr0: field(328),
    rtmr1: field(376),
    rtmr2: field(424),
  }
}

const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'))
const base = {
  ...mrsFromQuoteHex(fixture.quote),
  eventLog: fixture.event_log,
  vmConfig: fixture.vm_config,
}

test('wasm module has no imports', () => {
  const bytes = Buffer.from(wasmBase64, 'base64')
  const mod = new WebAssembly.Module(bytes)
  assert.deepEqual(WebAssembly.Module.imports(mod), [])
})

test('accepts the public TDX lite getquote fixture', () => {
  const result = verifyTdxLiteOs(base)
  assert.equal(result.ok, true, result.reason)
  assert.equal(result.acpiTablesVerified, true)
  assert.equal(typeof result.osImageHash, 'string')
  assert.equal(result.reason, null)
})

test('accepts mixed-case measurement hex', () => {
  const result = verifyTdxLiteOs({ ...base, mrtd: base.mrtd.toUpperCase() })
  assert.equal(result.ok, true, result.reason)
})

test('rejects tampered vm_config fields', () => {
  const vm = JSON.parse(fixture.vm_config)
  const cases = [
    ['memory_size', { memory_size: 4 * 1024 ** 3 }],
    ['pci_hole64_size', { pci_hole64_size: vm.pci_hole64_size === 0 ? 2 ** 50 : 0 }],
    ['hotplug_off', { hotplug_off: !vm.hotplug_off }],
    ['num_nics', { num_nics: 2 }],
    ['cpu_count', { cpu_count: vm.cpu_count + 1 }],
    ['qemu_version', { qemu_version: '9.2.1' }],
  ]
  for (const [name, patch] of cases) {
    const result = verifyTdxLiteOs({
      ...base,
      vmConfig: JSON.stringify({ ...vm, ...patch }),
    })
    assert.equal(result.ok, false, `${name} should be rejected`)
    assert.equal(typeof result.reason, 'string')
  }
})

test('rejects a tampered ACPI digest and RTMR2', () => {
  const events = JSON.parse(fixture.event_log)
  const index = events.findIndex((event) => event.event === 'acpi-tables')
  events[index] = {
    ...events[index],
    digest: events[index].digest.replace(/^./, (ch) => (ch === '0' ? '1' : '0')),
  }
  const acpi = verifyTdxLiteOs({ ...base, eventLog: JSON.stringify(events) })
  assert.equal(acpi.ok, false)
  assert.match(acpi.reason, /acpi-tables/)

  const rtmr2 = verifyTdxLiteOs({ ...base, rtmr2: '00'.repeat(48) })
  assert.equal(rtmr2.ok, false)
  assert.match(rtmr2.reason, /RTMR2/)
})

test('never throws on garbage input', () => {
  const result = verifyTdxLiteOs({
    mrtd: '',
    rtmr0: '',
    rtmr1: '',
    rtmr2: '',
    eventLog: '[]',
    vmConfig: '{}',
  })
  assert.equal(result.ok, false)
  assert.equal(typeof result.reason, 'string')
  assert.doesNotThrow(() => verifyTdxLiteOs(null))
  assert.doesNotThrow(() => verifyTdxLiteOs(undefined))
  assert.doesNotThrow(() => verifyTdxLiteOs({}))
})
