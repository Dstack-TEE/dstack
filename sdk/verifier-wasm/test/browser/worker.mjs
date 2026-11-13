// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { verifyTdxLiteOs } from '../../src/index.js'
import { buildCases, runCases } from '../cases.mjs'

const fixture = await fetch('/dstack/verifier/fixtures/tdx-lite-getquote.json').then((response) => {
  if (!response.ok) {
    throw new Error(`fixture HTTP ${response.status}`)
  }
  return response.json()
})
postMessage(runCases(verifyTdxLiteOs, buildCases(fixture)))
