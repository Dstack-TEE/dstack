// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { app } from 'electron'

import { verifyTdxLiteOs } from '../src/index.js'
import { buildCases, formatReport, runCases } from './cases.mjs'

function fail(err) {
  console.error(err && err.stack ? err.stack : err)
  app.exit(1)
}

process.on('uncaughtException', fail)
process.on('unhandledRejection', fail)

app.whenReady().then(() => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
  const fixturePath = join(root, 'dstack/verifier/fixtures/tdx-lite-getquote.json')
  const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'))
  const report = runCases(verifyTdxLiteOs, buildCases(fixture))
  console.log(formatReport(report))
  app.exit(report.failed.length > 0 ? 1 : 0)
}).catch(fail)
