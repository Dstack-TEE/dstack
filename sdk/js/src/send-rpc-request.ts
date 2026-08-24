// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import http from 'http'
import https from 'https'

export const __version__ = "0.6.0"

/**
 * How much of a server response an error may quote.
 *
 * An agent with no route for the path answers with an HTML page, and pasting
 * a whole page into an exception message helps nobody.
 */
const MAX_ERROR_BODY = 300

function truncate(text: string): string {
  return text.length > MAX_ERROR_BODY ? `${text.slice(0, MAX_ERROR_BODY)}...` : text
}

/**
 * What the server said, as far as it can be made out.
 *
 * A prpc handler that refuses answers `{"error": "..."}`, and that field is the
 * only part worth showing. A request that never reached a handler -- a `/v1`
 * call against a pre-0.6 agent -- comes back as an HTML error page instead, and
 * then the raw body is the only clue there is.
 */
function serverErrorText(body: string): string {
  const text = body.trim()
  if (!text) {
    return '(empty response body)'
  }
  try {
    const parsed = JSON.parse(text)
    if (parsed && typeof parsed === 'object' && typeof parsed.error === 'string') {
      return truncate(parsed.error)
    }
  } catch {
    // Not JSON, so the body is the message.
  }
  return truncate(text)
}

function httpError(statusCode: number, body: string): Error {
  return new Error(`HTTP ${statusCode}: ${serverErrorText(body)}`)
}

function parseError(body: string): Error {
  return new Error(`failed to parse response: ${truncate(body.trim())}`)
}

function isSuccess(statusCode: number): boolean {
  return statusCode >= 200 && statusCode < 300
}

export function send_rpc_request<T = any>(endpoint: string, path: string, payload: string, timeoutMs?: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const abortController = new AbortController()
    let isCompleted = false

    const safeReject = (error: Error) => {
      if (!isCompleted) {
        isCompleted = true
        reject(error)
      }
    }

    const safeResolve = (result: T) => {
      if (!isCompleted) {
        isCompleted = true
        resolve(result)
      }
    }

    // Reporting the status is the whole point of reading it: a caller that only
    // ever sees "failed to parse response" cannot tell a 404 from a corrupt
    // body, and 404 is what a pre-0.6 agent answers every `/v1` call with.
    const settle = (statusCode: number, body: string) => {
      if (!isSuccess(statusCode)) {
        safeReject(httpError(statusCode, body))
        return
      }
      try {
        safeResolve(JSON.parse(body) as T)
      } catch (error) {
        safeReject(parseError(body))
      }
    }

    const timeout = setTimeout(() => {
      abortController.abort()
      safeReject(new Error('request timed out'))
    }, timeoutMs || 30_000) // Default 30 seconds timeout

    const cleanup = () => {
      clearTimeout(timeout)
      abortController.signal.removeEventListener('abort', onAbort)
    }

    const onAbort = () => {
      cleanup()
      safeReject(new Error('request aborted'))
    }

    abortController.signal.addEventListener('abort', onAbort)

    const isHttp = endpoint.startsWith('http://') || endpoint.startsWith('https://')

    if (isHttp) {
      const url = new URL(path, endpoint)
      const options = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          'User-Agent': `dstack-sdk-js/${__version__}`,
        },
      }

      const req = (url.protocol === 'https:' ? https : http).request(url, options, (res) => {
        // Buffers, concatenated once at the end, rather than `data += chunk`.
        // Appending a Buffer to a string decodes that chunk on its own, so a
        // UTF-8 sequence split across two TCP reads becomes two replacement
        // characters -- and the call still resolves, with corrupted data.
        const chunks: Buffer[] = []
        res.on('data', (chunk) => {
          chunks.push(chunk)
        })
        res.on('end', () => {
          cleanup()
          settle(res.statusCode ?? 0, Buffer.concat(chunks).toString('utf8'))
        })
      })

      req.on('error', (error) => {
        cleanup()
        safeReject(error)
      })

      abortController.signal.addEventListener('abort', () => {
        req.destroy()
      })

      req.write(payload)
      req.end()
    } else {
      // `socketPath` rather than a hand-written request over `net`: node's HTTP
      // client already frames the request, de-chunks the response, and knows
      // that `Content-Length` counts bytes. The version this replaces did none
      // of those on the read path -- it compared a byte count from the header
      // against a JS string's UTF-16 length, so a response carrying one
      // non-ASCII character never satisfied its own end condition and the call
      // hung until the agent's keep-alive expired, ten seconds later. An
      // app-compose with an accented character in a comment was enough.
      const req = http.request(
        {
          socketPath: endpoint,
          path,
          method: 'POST',
          // One connection per call, closed when the response ends. The code
          // this replaces called `client.end()` explicitly; node's default
          // agent instead pools the socket, and an open socket keeps the
          // process alive -- a script that awaits one `info()` and returns
          // would hang until the agent's keep-alive expired.
          agent: false,
          headers: {
            Host: 'localhost',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            'User-Agent': `dstack-sdk-js/${__version__}`,
          },
        },
        (res) => {
          const chunks: Buffer[] = []
          res.on('data', (chunk) => {
            chunks.push(chunk)
          })
          res.on('end', () => {
            cleanup()
            settle(res.statusCode ?? 0, Buffer.concat(chunks).toString('utf8'))
          })
        },
      )

      req.on('error', (error) => {
        cleanup()
        safeReject(error)
      })

      abortController.signal.addEventListener('abort', () => {
        req.destroy()
      })

      req.write(payload)
      req.end()
    }
  })
}
