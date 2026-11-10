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
import { buildCases, runCases } from './cases.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const fixture = JSON.parse(
  readFileSync(join(root, 'dstack/verifier/fixtures/tdx-lite-getquote.json'), 'utf8'),
)

test('wasm module has no imports', () => {
  const bytes = Buffer.from(wasmBase64, 'base64')
  const mod = new WebAssembly.Module(bytes)
  assert.deepEqual(WebAssembly.Module.imports(mod), [])
})

const report = runCases(verifyTdxLiteOs, buildCases(fixture))
for (const result of report.results) {
  test(result.name, () => {
    assert.equal(result.ok, true, result.detail)
  })
}
