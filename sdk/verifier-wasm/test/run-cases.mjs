#!/usr/bin/env node
// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { verifyTdxLiteOs } from '../src/index.js'
import { wasmBase64 } from '../src/wasm-bytes.js'
import { buildCases, formatReport, runCases } from './cases.mjs'

const imports = WebAssembly.Module.imports(new WebAssembly.Module(Buffer.from(wasmBase64, 'base64')))
if (imports.length !== 0) {
  console.error('wasm module must not import anything:', imports)
  process.exit(1)
}

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const fixturePath = join(root, 'dstack/verifier/fixtures/tdx-lite-getquote.json')
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'))
const report = runCases(verifyTdxLiteOs, buildCases(fixture))
console.log(formatReport(report))
if (report.failed.length > 0) {
  process.exit(1)
}
