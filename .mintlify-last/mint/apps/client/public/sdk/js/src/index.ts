import net from 'net'
import crypto from 'crypto'
import http from 'http'
import https from 'https'
import { URL } from 'url'

export interface GetTlsKeyResponse {
  key: string
  certificate_chain: string[]

  asUint8Array: (max_length?: number) => Uint8Array
}

export interface GetKeyResponse {
  key: Uint8Array
  signature_chain: Uint8Array[]
}

export type Hex = `${string}`

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

export interface InfoResponse {
  app_id: string
  instance_id: string
  app_cert: string
  tcb_info: TcbInfo
  app_name: string
  public_logs: boolean
  public_sysinfo: boolean
  device_id: string
  mr_aggregated: string
  os_image_hash: string
  mr_key_provider: string
  key_provider_info: string
  compose_hash: string
}

export interface GetQuoteResponse {
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

export function send_rpc_request<T = any>(endpoint: string, path: string, payload: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const abortController = new AbortController()
    const timeout = setTimeout(() => {
      abortController.abort()
      reject(new Error('Request timed out'))
    }, 30_000) // 30 seconds timeout

    const isHttp = endpoint.startsWith('http://') || endpoint.startsWith('https://')

    if (isHttp) {
      const url = new URL(path, endpoint)
      const options = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
      }

      const req = (url.protocol === 'https:' ? https : http).request(url, options, (res) => {
        let data = ''
        res.on('data', (chunk) => {
          data += chunk
        })
        res.on('end', () => {
          clearTimeout(timeout)
          try {
            const result = JSON.parse(data)
            resolve(result as T)
          } catch (error) {
            reject(new Error('Failed to parse response'))
          }
        })
      })

      req.on('error', (error) => {
        clearTimeout(timeout)
        reject(error)
      })

      abortController.signal.addEventListener('abort', () => {
        req.destroy()
        reject(new Error('Request aborted'))
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
        clearTimeout(timeout)
        try {
          const result = JSON.parse(bodyData.slice(0, contentLength))
          resolve(result as T)
        } catch (error) {
          reject(new Error('Failed to parse response'))
        }
      })

      client.on('error', (error) => {
        clearTimeout(timeout)
        reject(error)
      })

      abortController.signal.addEventListener('abort', () => {
        client.destroy()
        reject(new Error('Request aborted'))
      })
    }
  })
}

export interface TlsKeyOptions {
  path?: string;
  subject?: string;
  altNames?: string[];
  usageRaTls?: boolean;
  usageServerAuth?: boolean;
  usageClientAuth?: boolean;
}

export class DstackClient {
  private endpoint: string

  constructor(endpoint: string = '/var/run/dstack.sock') {
    if (process.env.DSTACK_SIMULATOR_ENDPOINT) {
      console.warn(`Using simulator endpoint: ${process.env.DSTACK_SIMULATOR_ENDPOINT}`)
      endpoint = process.env.DSTACK_SIMULATOR_ENDPOINT
    }
    this.endpoint = endpoint
  }

  async getKey(path: string, purpose: string = ''): Promise<GetKeyResponse> {
    const payload = JSON.stringify({
      path: path,
      purpose: purpose
    })
    const result = await send_rpc_request<{ key: string, signature_chain: string[] }>(this.endpoint, '/GetKey', payload)
    return Object.freeze({
      key: new Uint8Array(Buffer.from(result.key, 'hex')),
      signature_chain: result.signature_chain.map(sig => new Uint8Array(Buffer.from(sig, 'hex')))
    })
  }

  async getTlsKey(options: TlsKeyOptions = {}): Promise<GetTlsKeyResponse> {
    const {
      subject = '',
      altNames = [],
      usageRaTls = false,
      usageServerAuth = true,
      usageClientAuth = false,
    } = options;

    let raw: Record<string, any> = {
      subject,
      usage_ra_tls: usageRaTls,
      usage_server_auth: usageServerAuth,
      usage_client_auth: usageClientAuth,
    }
    if (altNames && altNames.length) {
      raw['alt_names'] = altNames
    }
    const payload = JSON.stringify(raw)
    const result = await send_rpc_request<GetTlsKeyResponse>(this.endpoint, '/GetTlsKey', payload)
    Object.defineProperty(result, 'asUint8Array', {
      get: () => (length?: number) => x509key_to_uint8array(result.key, length),
      enumerable: true,
      configurable: false,
    })
    return Object.freeze(result)
  }

  async getQuote(report_data: string | Buffer | Uint8Array): Promise<GetQuoteResponse> {
    let hex = to_hex(report_data)
    if (hex.length > 128) {
      throw new Error(`Report data is too large, it should be less than 64 bytes.`)
    }
    const payload = JSON.stringify({ report_data: hex })
    const result = await send_rpc_request<GetQuoteResponse>(this.endpoint, '/GetQuote', payload)
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

  async info(): Promise<InfoResponse> {
    const result = await send_rpc_request<Omit<InfoResponse, 'tcb_info'> & { tcb_info: string }>(this.endpoint, '/Info', '{}')
    return Object.freeze({
      ...result,
      tcb_info: JSON.parse(result.tcb_info) as TcbInfo,
    })
  }

  /**
   * Emit an event. This extends the event to RTMR3 on TDX platform.
   *
   * Requires Dstack OS 0.5.0 or later.
   *
   * @param event The event name
   * @param payload The event data as string or Buffer or Uint8Array
   */
  async emitEvent(event: string, payload: string | Buffer | Uint8Array): Promise<void> {
    if (!event) {
      throw new Error('Event name cannot be empty')
    }

    const hexPayload = to_hex(payload)
    await send_rpc_request(
      this.endpoint,
      '/EmitEvent',
      JSON.stringify({
        event: event,
        payload: hexPayload
      })
    )
  }
}
