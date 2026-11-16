// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { buildCases, formatReport, runCases } from '../cases.mjs'

function errorMessage(err) {
  if (err && err.message) {
    return err.message
  }
  return String(err)
}

const result = { main: null, worker: null, errors: [] }

try {
  const fixture = await fetch('/dstack/verifier/fixtures/tdx-lite-getquote.json').then((response) => {
    if (!response.ok) {
      throw new Error(`fixture HTTP ${response.status}`)
    }
    return response.json()
  })
  const { verifyTdxLiteOs } = await import('../../src/index.js')
  result.main = runCases(verifyTdxLiteOs, buildCases(fixture))
} catch (err) {
  result.errors.push({ where: 'main', message: errorMessage(err) })
}

try {
  result.worker = await new Promise((resolve, reject) => {
    const worker = new Worker('./worker.mjs', { type: 'module' })
    worker.onmessage = (event) => resolve(event.data)
    worker.onerror = (event) => {
      reject(new Error(event.message || 'worker error'))
    }
  })
} catch (err) {
  result.errors.push({ where: 'worker', message: errorMessage(err) })
}

window.__RESULT__ = result
window.__DONE__ = true

const lines = []
if (result.main) {
  lines.push('main thread', formatReport(result.main))
}
if (result.worker) {
  lines.push('worker', formatReport(result.worker))
}
for (const err of result.errors) {
  lines.push(`ERROR ${err.where}: ${err.message}`)
}
document.getElementById('out').textContent = lines.join('\n')
