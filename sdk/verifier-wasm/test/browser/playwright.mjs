#!/usr/bin/env node
// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { createServer } from 'node:http'
import { readFileSync, statSync } from 'node:fs'
import { extname, join, normalize, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const browserName = process.argv[2]
if (!browserName) {
  console.error('usage: playwright.mjs <chromium|firefox|webkit>')
  process.exit(1)
}

const root = resolve(fileURLToPath(new URL('../../../../', import.meta.url)))
const mime = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.wasm': 'application/wasm',
}

function isInsideRoot(path) {
  const resolved = resolve(path)
  return resolved === root || resolved.startsWith(root + sep)
}

const server = createServer((request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1')
  const path = normalize(join(root, decodeURIComponent(url.pathname)))
  if (!isInsideRoot(path)) {
    response.writeHead(403)
    response.end()
    return
  }
  try {
    if (!statSync(path).isFile()) {
      response.writeHead(404)
      response.end()
      return
    }
    const body = readFileSync(path)
    response.writeHead(200, {
      'content-type': mime[extname(path)] || 'application/octet-stream',
      'cache-control': 'no-store',
    })
    response.end(body)
  } catch {
    response.writeHead(404)
    response.end()
  }
})

await new Promise((resolveListen) => {
  server.listen(0, '127.0.0.1', resolveListen)
})
const { port } = server.address()
const pageUrl = `http://127.0.0.1:${port}/sdk/verifier-wasm/test/browser/index.html`

const playwright = await import('playwright')
const launcher = playwright[browserName]
if (!launcher) {
  console.error(`unknown browser ${browserName}`)
  process.exit(1)
}

const browser = await launcher.launch()
const page = await browser.newPage()
const pageErrors = []
page.on('pageerror', (err) => {
  pageErrors.push(err && err.stack ? err.stack : String(err))
})
page.on('console', (msg) => {
  if (msg.type() === 'error') {
    pageErrors.push(`console.error: ${msg.text()}`)
  }
})

try {
  await page.goto(pageUrl, { waitUntil: 'domcontentloaded' })
  await page.waitForFunction(() => window.__DONE__ === true, null, { timeout: 60_000 })
} catch (err) {
  console.error(`${browserName} page did not finish:`)
  console.error(err && err.message ? err.message : err)
  if (pageErrors.length > 0) {
    console.error(pageErrors.join('\n'))
  }
  await browser.close()
  server.close()
  process.exit(1)
}

const result = await page.evaluate(() => window.__RESULT__)
await browser.close()
server.close()

let failed = pageErrors.length > 0 || result.errors.length > 0
for (const err of result.errors) {
  console.error(`${browserName} ${err.where}: ${err.message}`)
}
for (const err of pageErrors) {
  console.error(`${browserName} pageerror: ${err}`)
}
for (const where of ['main', 'worker']) {
  const report = result[where]
  if (!report) {
    failed = true
    console.error(`${browserName} ${where}: no report`)
    continue
  }
  console.log(`${browserName} ${where}: ${report.passed} passed, ${report.failed.length} failed`)
  for (const row of report.results) {
    console.log(`${row.ok ? 'PASS' : 'FAIL'}  ${where}  ${row.name}${row.detail ? `  -- ${row.detail}` : ''}`)
  }
  if (report.failed.length > 0) {
    failed = true
  }
}

if (failed) {
  process.exit(1)
}
