// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import http from 'http'
import https from 'https'
import net from 'net'

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

/**
 * Read the status code out of an HTTP status line (`HTTP/1.1 404 Not Found`).
 *
 * Exported for the unix-socket branch's tests: that branch speaks HTTP by hand,
 * so nothing else parses this for it. An unreadable line yields 0, which is not
 * a success code and so gets reported rather than passed off as one.
 */
export function parse_status_code(statusLine: string): number {
  const code = Number.parseInt(statusLine.split(' ')[1], 10)
  return Number.isNaN(code) ? 0 : code
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
        let data = ''
        res.on('data', (chunk) => {
          data += chunk
        })
        res.on('end', () => {
          cleanup()
          settle(res.statusCode ?? 0, data)
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
      const client = net.createConnection({ path: endpoint }, () => {
        client.write(`POST ${path} HTTP/1.1\r\n`)
        client.write(`Host: localhost\r\n`)
        client.write(`Content-Type: application/json\r\n`)
        // Byte length, not `payload.length`: JS strings count UTF-16 code units
        // and the socket emits UTF-8, so any non-ASCII field -- a `getKey`
        // domain, a certificate subject -- declared a body shorter than the one
        // sent. The agent then parsed truncated JSON and the surplus bytes were
        // left in the stream to corrupt whatever read next.
        client.write(`Content-Length: ${Buffer.byteLength(payload)}\r\n`)
        client.write('\r\n')
        client.write(payload)
      })

      let data = ''
      let headers: Record<string, string> = {}
      let headersParsed = false
      let statusCode = 0
      let contentLength = 0
      let bodyData = ''

      client.on('data', (chunk) => {
        data += chunk
        if (!headersParsed) {
          const headerEndIndex = data.indexOf('\r\n\r\n')
          if (headerEndIndex !== -1) {
            const headerLines = data.slice(0, headerEndIndex).split('\r\n')
            // The first line is the status line, not a header.
            statusCode = parse_status_code(headerLines[0])
            headerLines.slice(1).forEach(line => {
              const [key, value] = line.split(': ')
              if (key && value) {
                headers[key.toLowerCase()] = value
              }
            })
            headersParsed = true
            contentLength = parseInt(headers['content-length'] || '0', 10)
            bodyData = data.slice(headerEndIndex + 4)
          }
        } else {
          bodyData += chunk
        }

        if (headersParsed && bodyData.length >= contentLength) {
          client.end()
        }
      })

      client.on('end', () => {
        cleanup()
        settle(statusCode, bodyData.slice(0, contentLength))
      })

      client.on('error', (error) => {
        cleanup()
        safeReject(error)
      })

      abortController.signal.addEventListener('abort', () => {
        client.destroy()
      })
    }
  })
}
