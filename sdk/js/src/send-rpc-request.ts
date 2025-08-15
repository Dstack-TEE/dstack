// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import http from 'http'
import https from 'https'
import net from 'net'

export const __version__ = "0.5.0"


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
          try {
            const result = JSON.parse(data)
            safeResolve(result as T)
          } catch (error) {
            safeReject(new Error('failed to parse response'))
          }
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
        client.write(`Content-Length: ${payload.length}\r\n`)
        client.write('\r\n')
        client.write(payload)
      })

      let data = ''
      let headers: Record<string, string> = {}
      let headersParsed = false
      let contentLength = 0
      let bodyData = ''

      client.on('data', (chunk) => {
        data += chunk
        if (!headersParsed) {
          const headerEndIndex = data.indexOf('\r\n\r\n')
          if (headerEndIndex !== -1) {
            const headerLines = data.slice(0, headerEndIndex).split('\r\n')
            headerLines.forEach(line => {
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
        try {
          const result = JSON.parse(bodyData.slice(0, contentLength))
          safeResolve(result as T)
        } catch (error) {
          safeReject(new Error('failed to parse response'))
        }
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