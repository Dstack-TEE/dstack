// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { wasmBase64 } from './wasm-bytes.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

function decodeBase64(value) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(value, 'base64')
  }
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

const wasmBytes = decodeBase64(wasmBase64)
const wasmModule = new WebAssembly.Module(wasmBytes)

let instance = null

function instantiate() {
  instance = new WebAssembly.Instance(wasmModule, {})
  return instance
}

function getExports() {
  if (instance === null) {
    instantiate()
  }
  return instance.exports
}

function failed(reason) {
  return {
    ok: false,
    osImageHash: null,
    reason: reason == null ? 'verification failed' : String(reason),
  }
}

function readOutput(exports, raw) {
  const result = BigInt(raw)
  const ptr = Number(result >> 32n)
  const len = Number(result & 0xffffffffn)
  const json = JSON.parse(decoder.decode(new Uint8Array(exports.memory.buffer, ptr, len)))
  exports.dealloc(ptr, len)
  return {
    ok: Boolean(json.ok),
    osImageHash: json.ok ? (json.os_image_hash ?? null) : null,
    reason: json.reason ?? null,
  }
}

function call(input) {
  const payload = encoder.encode(
    JSON.stringify({
      mrtd: input.mrtd,
      rtmr0: input.rtmr0,
      rtmr1: input.rtmr1,
      rtmr2: input.rtmr2,
      event_log: input.eventLog,
      vm_config: input.vmConfig,
    }),
  )
  const exports = getExports()
  const ptr = exports.alloc(payload.length)
  new Uint8Array(exports.memory.buffer, ptr, payload.length).set(payload)
  const raw = exports.verify_tdx_lite(ptr, payload.length)
  exports.dealloc(ptr, payload.length)
  return readOutput(exports, raw)
}

export function verifyTdxLiteOs(input) {
  try {
    if (input == null || typeof input !== 'object') {
      return failed('input must be an object')
    }
    return call(input)
  } catch (err) {
    instance = null
    try {
      instantiate()
    } catch (instantiateErr) {
      return failed(instantiateErr && instantiateErr.message ? instantiateErr.message : instantiateErr)
    }
    return failed(err && err.message ? err.message : err)
  }
}
