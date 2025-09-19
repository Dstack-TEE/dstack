// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import fs from 'fs'
import crypto from 'crypto'
import { send_rpc_request } from './send-rpc-request'
export { getComposeHash } from './get-compose-hash'
export { verifyEnvEncryptPublicKey } from './verify-env-encrypt-public-key'

export interface GetTlsKeyResponse {
  __name__: Readonly<'GetTlsKeyResponse'>

  key: string
  certificate_chain: string[]

  asUint8Array: (max_length?: number) => Uint8Array
}

export interface GetKeyResponse {
  __name__: Readonly<'GetKeyResponse'>

  key: Uint8Array
  signature_chain: Uint8Array[]
}

export type Hex = `${string}`

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
  rtmr0: string
  rtmr1: string
  rtmr2: string
  rtmr3: string
  app_compose: string
  event_log: EventLog[]
}

export type TcbInfoV03x = TcbInfo & {
  rootfs_hash?: string
}

export type TcbInfoV05x = TcbInfo & {
  mr_aggregated: string
  os_image_hash: string
  compose_hash: string
  device_id: string
}

export interface InfoResponse<VersionTcbInfo extends TcbInfo> {
  app_id: string
  instance_id: string
  app_cert: string
  tcb_info: VersionTcbInfo
  app_name: string
  device_id: string
  os_image_hash?: string // Optional: empty if OS image is not measured by KMS
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
    mr = Buffer.from(crypto.createHash('sha384')
      .update(Buffer.concat([mr, contentBuffer]))
      .digest())
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

export interface TlsKeyOptions {
  path?: string;
  subject?: string;
  altNames?: string[];
  usageRaTls?: boolean;
  usageServerAuth?: boolean;
  usageClientAuth?: boolean;
}

export class DstackClient<T extends TcbInfo = TcbInfoV05x> {
  protected endpoint: string

  constructor(endpoint: string | undefined = undefined) {
    if (endpoint === undefined) {
      if (process.env.DSTACK_SIMULATOR_ENDPOINT) {
        console.warn(`Using simulator endpoint: ${process.env.DSTACK_SIMULATOR_ENDPOINT}`)
        endpoint = process.env.DSTACK_SIMULATOR_ENDPOINT
      } else {
        endpoint = '/var/run/dstack.sock'
      }
    }
    if (endpoint.startsWith('/') && !fs.existsSync(endpoint)) {
      throw new Error(`Unix socket file ${endpoint} does not exist`);
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
      signature_chain: result.signature_chain.map(sig => new Uint8Array(Buffer.from(sig, 'hex'))),
      __name__: 'GetKeyResponse',
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
    const asUint8Array = (length?: number) => x509key_to_uint8array(result.key, length)
    return Object.freeze({
      ...result,
      asUint8Array,
      __name__: 'GetTlsKeyResponse',
    })
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

  async info(): Promise<InfoResponse<T>> {
    const result = await send_rpc_request<Omit<InfoResponse<TcbInfo>, 'tcb_info'> & { tcb_info: string }>(this.endpoint, '/Info', '{}')
    return Object.freeze({
      ...result,
      tcb_info: JSON.parse(result.tcb_info) as T,
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

  /**
   * Emit an event. This extends the event to RTMR3 on TDX platform.
   *
   * Requires dstack OS 0.5.0 or later.
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

  //
  // Legacy methods for backward compatibility with a warning to notify users about migrating to new methods.
  // These methods don't mean fully compatible as past, but we keep them here until next major version.
  //

  /**
   * @deprecated Use getKey instead.
   * @param path The path to the key.
   * @param subject The subject of the key.
   * @param altNames The alternative names of the key.
   * @returns The key.
   */
  async deriveKey(path?: string, subject?: string, altNames?: string[]): Promise<GetTlsKeyResponse> {
    throw new Error('deriveKey is deprecated, please use getKey instead.')
  }

  /**
   * @deprecated Use getQuote instead.
   * @param report_data The report data.
   * @param hash_algorithm The hash algorithm.
   * @returns The quote.
   */
  async tdxQuote(report_data: string | Buffer | Uint8Array, hash_algorithm?: TdxQuoteHashAlgorithms): Promise<GetQuoteResponse> {
    console.warn('tdxQuote is deprecated, please use getQuote instead')
    if (hash_algorithm !== "raw") {
      throw new Error('tdxQuote only supports raw hash algorithm.')
    }
    return this.getQuote(report_data)
  }
}

export class TappdClient extends DstackClient<TcbInfoV03x> {
  constructor(endpoint: string | undefined = undefined) {
    if (endpoint === undefined) {
      if (process.env.TAPPD_SIMULATOR_ENDPOINT) {
        console.warn(`Using tappd endpoint: ${process.env.TAPPD_SIMULATOR_ENDPOINT}`)
        endpoint = process.env.TAPPD_SIMULATOR_ENDPOINT
      } else {
        endpoint = '/var/run/tappd.sock'
      }
    }
    console.warn('TappdClient is deprecated, please use DstackClient instead')
    super(endpoint)
  }

  /**
   * @deprecated Use getKey instead.
   * @param path The path to the key.
   * @param subject The subject of the key.
   * @param altNames The alternative names of the key.
   * @returns The key.
   */
  async deriveKey(path?: string, subject?: string, alt_names?: string[]): Promise<GetTlsKeyResponse> {
    console.warn('deriveKey is deprecated, please use getKey instead');
    let raw: Record<string, any> = { path: path || '', subject: subject || path || '' }
    if (alt_names && alt_names.length) {
      raw['alt_names'] = alt_names
    }
    const payload = JSON.stringify(raw)
    const result = await send_rpc_request<GetTlsKeyResponse>(this.endpoint, '/prpc/Tappd.DeriveKey', payload)
    const asUint8Array = (length?: number) => x509key_to_uint8array(result.key, length)
    return Object.freeze({
      ...result,
      asUint8Array,
      __name__: 'GetTlsKeyResponse',
    })
  }

  /**
   * @deprecated Use getQuote instead.
   * @param report_data The report data.
   * @param hash_algorithm The hash algorithm.
   * @returns The quote.
   */
  async tdxQuote(report_data: string | Buffer | Uint8Array, hash_algorithm?: TdxQuoteHashAlgorithms): Promise<GetQuoteResponse> {
    console.warn('tdxQuote is deprecated, please use getQuote instead');
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
    const result = await send_rpc_request<GetQuoteResponse>(this.endpoint, '/prpc/Tappd.TdxQuote', payload)
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
}