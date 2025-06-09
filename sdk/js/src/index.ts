import net from 'net'
import crypto from 'crypto'
import http from 'http'
import https from 'https'
import { URL } from 'url'

export const __version__ = "0.2.1"

export interface DeriveKeyResponse {
  key: string
  certificate_chain: string[]

  asUint8Array: (max_length?: number) => Uint8Array
}

export type Hex = `0x${string}`

export type TdxQuoteHashAlgorithms =
  'sha256' | 'sha384' | 'sha512' | 'sha3-256' | 'sha3-384' | 'sha3-512' |
  'keccak256' | 'keccak384' | 'keccak512' | 'raw'

export interface EventLog {
  imr: number
  event_type: number
  digest: string
  event: string
  event_payload: string
}

export interface TcbInfo {
  mrtd: string
  rootfs_hash: string
  rtmr0: string
  rtmr1: string
  rtmr2: string
  rtmr3: string
  event_log: EventLog[]
}

export interface TappdInfoResponse {
  app_id: string
  instance_id: string
  app_cert: string
  tcb_info: TcbInfo
  app_name: string
  public_logs: boolean
  public_sysinfo: boolean
}

export interface TdxQuoteResponse {
  quote: Hex
  event_log: string

  replayRtmrs: () => string[]
}

export function to_hex(data: string | Buffer | Uint8Array): string {
  if (typeof data === 'string') {
    return Buffer.from(data).toString('hex');
  }
  if (data instanceof Uint8Array) {
    return Buffer.from(data).toString('hex');
  }
  return (data as Buffer).toString('hex');
}

function x509key_to_uint8array(pem: string, max_length?: number) {
  const content = pem.replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\n/g, '');
  const binaryDer = atob(content)
  if (!max_length) {
    max_length = binaryDer.length
  }
  const result = new Uint8Array(max_length)
  for (let i = 0; i < max_length; i++) {
    result[i] = binaryDer.charCodeAt(i)
  }
  return result
}

function replay_rtmr(history: string[]): string {
  const INIT_MR = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  if (history.length === 0) {
      return INIT_MR
  }
  let mr = Buffer.from(INIT_MR, 'hex')
  for (const content of history) {
      // Convert hex string to buffer
      let contentBuffer = Buffer.from(content, 'hex')
      // Pad content with zeros if shorter than 48 bytes
      if (contentBuffer.length < 48) {
          const padding = Buffer.alloc(48 - contentBuffer.length, 0)
          contentBuffer = Buffer.concat([contentBuffer, padding])
      }
      mr = crypto.createHash('sha384')
          .update(Buffer.concat([mr, contentBuffer]))
          .digest()
  }
  return mr.toString('hex')
}

function reply_rtmrs(event_log: EventLog[]): Record<number, string> {
  const rtmrs: Array<string> = []
  for (let idx = 0; idx < 4; idx++) {
      const history = event_log
          .filter(event => event.imr === idx)
          .map(event => event.digest)
      rtmrs[idx] = replay_rtmr(history)
  }
  return rtmrs
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

export class TappdClient {
  private endpoint: string

  constructor(endpoint: string = '/var/run/tappd.sock') {
    if (process.env.DSTACK_SIMULATOR_ENDPOINT) {
      console.debug(`Using simulator endpoint: ${process.env.DSTACK_SIMULATOR_ENDPOINT}`)
      endpoint = process.env.DSTACK_SIMULATOR_ENDPOINT
    }
    this.endpoint = endpoint
  }

  async deriveKey(path?: string, subject?: string, alt_names?: string[]): Promise<DeriveKeyResponse> {
    let raw: Record<string, any> = { path: path || '', subject: subject || path || '' }
    if (alt_names && alt_names.length) {
      raw['alt_names'] = alt_names
    }
    const payload = JSON.stringify(raw)
    const result = await send_rpc_request<DeriveKeyResponse>(this.endpoint, '/prpc/Tappd.DeriveKey', payload)
    Object.defineProperty(result, 'asUint8Array', {
      get: () => (length?: number) => x509key_to_uint8array(result.key, length),
      enumerable: true,
      configurable: false,
    })
    return Object.freeze(result)
  }

  async tdxQuote(report_data: string | Buffer | Uint8Array, hash_algorithm?: TdxQuoteHashAlgorithms): Promise<TdxQuoteResponse> {
    let hex = to_hex(report_data)
    if (hash_algorithm === 'raw') {
      if (hex.length > 128) {
        throw new Error(`Report data is too large, it should less then 64 bytes when hash_algorithm is raw.`)
      }
      if (hex.length < 128) {
        hex = hex.padStart(128, '0')
      }
    }
    const payload = JSON.stringify({ report_data: hex, hash_algorithm })
    const result = await send_rpc_request<TdxQuoteResponse>(this.endpoint, '/prpc/Tappd.TdxQuote', payload)
    if ('error' in result) {
      const err = result['error'] as string
      throw new Error(err)
    }
    Object.defineProperty(result, 'replayRtmrs', {
      get: () => () => reply_rtmrs(JSON.parse(result.event_log) as EventLog[]),
      enumerable: true,
      configurable: false,
    })
    return Object.freeze(result)
  }

  async info(): Promise<TappdInfoResponse> {
    const result = await send_rpc_request<Omit<TappdInfoResponse, 'tcb_info'> & { tcb_info: string }>(this.endpoint, '/prpc/Tappd.Info', '{}')
    return Object.freeze({
      ...result,
      tcb_info: JSON.parse(result.tcb_info) as TcbInfo,
    })
  }

  async isReachable(): Promise<boolean> {
    try {
      // Use info endpoint to test connectivity with 500ms timeout
      await send_rpc_request(this.endpoint, '/prpc/Tappd.Info', '{}', 500)
      return true
    } catch (error) {
      return false
    }
  }
}
