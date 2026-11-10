// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes) {
  let hex = ''
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return hex
}

export function mrsFromQuoteHex(quoteHex) {
  const quote = hexToBytes(quoteHex)
  const version = quote[0] | (quote[1] << 8)
  const header = version === 5 ? 54 : 48
  const field = (offset) => bytesToHex(quote.subarray(header + offset, header + offset + 48))
  return {
    mrtd: field(136),
    rtmr0: field(328),
    rtmr1: field(376),
    rtmr2: field(424),
  }
}

export function buildCases(fixture) {
  const base = {
    ...mrsFromQuoteHex(fixture.quote),
    eventLog: fixture.event_log,
    vmConfig: fixture.vm_config,
  }
  const vm = JSON.parse(fixture.vm_config)
  const events = JSON.parse(fixture.event_log)
  const acpiIndex = events.findIndex((event) => event.event === 'acpi-tables')
  const tamperedEvents = events.slice()
  tamperedEvents[acpiIndex] = {
    ...events[acpiIndex],
    digest: events[acpiIndex].digest.replace(/^./, (ch) => (ch === '0' ? '1' : '0')),
  }

  const vmTampers = [
    ['memory_size', { memory_size: 4 * 1024 ** 3 }],
    ['pci_hole64_size', { pci_hole64_size: vm.pci_hole64_size === 0 ? 2 ** 50 : 0 }],
    ['hotplug_off', { hotplug_off: !vm.hotplug_off }],
    ['num_nics', { num_nics: 2 }],
    ['cpu_count', { cpu_count: vm.cpu_count + 1 }],
    ['qemu_version', { qemu_version: '9.2.1' }],
  ]

  return [
    {
      name: 'accepts the public TDX lite getquote fixture',
      input: base,
      expect: { ok: true, osImageHash: vm.os_image_hash, reason: null },
    },
    {
      name: 'accepts mixed-case measurement hex',
      input: { ...base, mrtd: base.mrtd.toUpperCase() },
      expect: { ok: true, osImageHash: vm.os_image_hash },
    },
    {
      name: 'does not return a stuffed os_image_hash on failure',
      input: {
        ...base,
        vmConfig: JSON.stringify({ ...vm, os_image_hash: 'ab'.repeat(32) }),
      },
      expect: { ok: false, osImageHash: null, reason: 'string' },
    },
    ...vmTampers.map(([name, patch]) => ({
      name: `rejects tampered ${name}`,
      input: { ...base, vmConfig: JSON.stringify({ ...vm, ...patch }) },
      expect: { ok: false, osImageHash: null, reason: 'string' },
    })),
    {
      name: 'rejects a tampered ACPI digest',
      input: { ...base, eventLog: JSON.stringify(tamperedEvents) },
      expect: { ok: false, osImageHash: null, reasonIncludes: 'acpi-tables' },
    },
    {
      name: 'rejects zeroed RTMR2',
      input: { ...base, rtmr2: '00'.repeat(48) },
      expect: { ok: false, osImageHash: null, reasonIncludes: 'RTMR2' },
    },
    {
      name: 'rejects garbage measurements without throwing',
      input: {
        mrtd: '',
        rtmr0: '',
        rtmr1: '',
        rtmr2: '',
        eventLog: '[]',
        vmConfig: '{}',
      },
      expect: { ok: false, osImageHash: null, reason: 'string', throws: false },
    },
    {
      name: 'rejects null input without throwing',
      input: null,
      expect: { ok: false, osImageHash: null, throws: false },
    },
    {
      name: 'rejects undefined input without throwing',
      input: undefined,
      expect: { ok: false, osImageHash: null, throws: false },
    },
    {
      name: 'rejects empty object without throwing',
      input: {},
      expect: { ok: false, osImageHash: null, throws: false },
    },
  ]
}

function checkExpect(expect, output, threw) {
  if (threw) {
    return expect.throws === true ? null : `threw: ${threw}`
  }
  if (expect.throws === true) {
    return 'expected a throw'
  }
  if (Boolean(output.ok) !== Boolean(expect.ok)) {
    return `ok=${output.ok} reason=${output.reason}`
  }
  if (Object.prototype.hasOwnProperty.call(expect, 'osImageHash')
    && output.osImageHash !== expect.osImageHash) {
    return `osImageHash=${output.osImageHash}`
  }
  if (expect.reason === null && output.reason != null) {
    return `reason=${output.reason}`
  }
  if (expect.reason === 'string' && typeof output.reason !== 'string') {
    return `reason type ${typeof output.reason}`
  }
  if (expect.reasonIncludes && (typeof output.reason !== 'string'
    || !output.reason.includes(expect.reasonIncludes))) {
    return `reason=${output.reason}`
  }
  return null
}

export function runCases(verifyTdxLiteOs, cases) {
  const results = []
  for (const testCase of cases) {
    let output = null
    let threw = null
    try {
      output = verifyTdxLiteOs(testCase.input)
    } catch (err) {
      threw = err && err.message ? err.message : String(err)
    }
    const detail = checkExpect(testCase.expect, output, threw)
    results.push({
      name: testCase.name,
      ok: detail === null,
      detail,
      threw,
      output,
    })
  }
  return {
    passed: results.filter((result) => result.ok).length,
    failed: results.filter((result) => !result.ok),
    results,
  }
}

export function formatReport(report) {
  const lines = report.results.map((result) => {
    if (result.ok) {
      return `PASS  ${result.name}`
    }
    return `FAIL  ${result.name}  -- ${result.detail}`
  })
  lines.push(`${report.passed} passed, ${report.failed.length} failed`)
  return lines.join('\n')
}
