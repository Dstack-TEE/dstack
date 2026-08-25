// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// The frozen v0 guest-agent surface: `DstackClientV0` and the `TappdClient`
// that predates it, plus the response types they alone return. Nothing here
// changes again -- see `DstackClientV0` for why.

import fs from 'fs'
import { send_rpc_request } from './send-rpc-request'
import { to_hex, throwOnRpcError, resolveDstackEndpoint, type Hex } from './shared'

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

export interface SignResponse {
  __name__: Readonly<'SignResponse'>

  signature: Uint8Array
  signature_chain: Uint8Array[]
  public_key: Uint8Array
}

export interface VerifyResponse {
  __name__: Readonly<'VerifyResponse'>

  valid: boolean
}

export type TdxQuoteHashAlgorithms =
  'sha256' | 'sha384' | 'sha512' | 'sha3-256' | 'sha3-384' | 'sha3-512' |
  'keccak256' | 'keccak384' | 'keccak512' | 'raw'

export interface EventLog {
  imr: number
  event_type: number
  digest: string
  event: string
  event_payload: string
  version?: 1 | 2
  preimage?: string
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
  mr_aggregated?: string
  os_image_hash?: string // Optional: empty if OS image is not measured by KMS
  key_provider_info: string
  compose_hash: string
  vm_config?: string
  // Cloud provider sys_vendor (e.g. "Google"). Available on dstack OS >= 0.5.7.
  cloud_vendor?: string
  // Cloud provider product_name (e.g. "Google Compute Engine"). Available on dstack OS >= 0.5.7.
  cloud_product?: string
}

export interface GetQuoteResponse {
  quote: Hex
  event_log: string
  report_data?: Hex
  vm_config?: string
}

export interface AttestResponse {
  __name__: Readonly<'AttestResponse'>

  attestation: Hex
}

export interface VersionResponse {
  __name__: Readonly<'VersionResponse'>

  version: string
  rev: string
}

// The v0 byte accessor, and v0's alone: the chain adapters feed it into seed
// derivation, so its truncating and zero-padding behaviour is load-bearing on
// the frozen surface. v1's IssueCert hands back PEM and nothing else.
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

export interface TlsKeyOptions {
  subject?: string;
  altNames?: string[];
  usageRaTls?: boolean;
  usageServerAuth?: boolean;
  usageClientAuth?: boolean;
  // Certificate validity start (seconds since UNIX epoch). Requires dstack OS >= 0.5.7.
  notBefore?: number;
  // Certificate validity end (seconds since UNIX epoch). Requires dstack OS >= 0.5.7.
  notAfter?: number;
  // Embed app info into the certificate. Requires dstack OS >= 0.5.7.
  withAppInfo?: boolean;
}

const SECP256K1_ALGORITHMS = new Set(['secp256k1', 'k256', ''])

/**
 * Client for the frozen v0 guest agent surface, served at `/<Method>` and,
 * since dstack 0.6.0, equivalently at `/v0/<Method>`.
 *
 * This surface is closed at the dstack 0.5.11 shape and will not change again.
 * New capability lands in `DstackClientV1`, which derives *different* key
 * material for the same inputs -- the two are separate derivation trees, not
 * two spellings of one.
 *
 * @deprecated Legacy surface, kept for apps that already published v0-derived
 * material and therefore cannot move. Use `DstackClientV1`, which the
 * unsuffixed `DstackClient` now names, for anything new.
 */
export class DstackClientV0<T extends TcbInfo = TcbInfoV05x> {
  protected endpoint: string

  constructor(endpoint: string | undefined = undefined) {
    this.endpoint = resolveDstackEndpoint(endpoint)
  }

  private async ensureAlgorithmSupported(algorithm: string): Promise<void> {
    if (SECP256K1_ALGORITHMS.has(algorithm)) return
    try {
      await this.version()
    } catch {
      throw new Error(`algorithm "${algorithm}" is not supported: OS version too old (Version RPC unavailable)`)
    }
  }

  private async ensureTlsKeyOptionsSupported(featureNames: string[]): Promise<void> {
    try {
      await this.version()
    } catch {
      throw new Error(`TLS key options [${featureNames.join(', ')}] are not supported: OS version too old (Version RPC unavailable)`)
    }
  }

  async getKey(path: string = '', purpose: string = '', algorithm: string = 'secp256k1'): Promise<GetKeyResponse> {
    await this.ensureAlgorithmSupported(algorithm)
    const payload = JSON.stringify({
      path: path,
      purpose: purpose,
      algorithm: algorithm
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
      notBefore,
      notAfter,
      withAppInfo,
    } = options;

    const newFeatures: string[] = []
    if (notBefore !== undefined) newFeatures.push('notBefore')
    if (notAfter !== undefined) newFeatures.push('notAfter')
    if (withAppInfo !== undefined) newFeatures.push('withAppInfo')
    if (newFeatures.length > 0) {
      await this.ensureTlsKeyOptionsSupported(newFeatures)
    }

    let raw: Record<string, any> = {
      subject,
      usage_ra_tls: usageRaTls,
      usage_server_auth: usageServerAuth,
      usage_client_auth: usageClientAuth,
    }
    if (altNames && altNames.length) {
      raw['alt_names'] = altNames
    }
    if (notBefore !== undefined) {
      raw['not_before'] = notBefore
    }
    if (notAfter !== undefined) {
      raw['not_after'] = notAfter
    }
    if (withAppInfo !== undefined) {
      raw['with_app_info'] = withAppInfo
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

  /**
   * Request a TDX quote for the given report data.
   *
   * Needs Intel TDX. Without it the guest agent returns an error and this
   * throws, and on GCP Confidential VMs it answers with the TDX quote alone,
   * leaving out the vTPM quote GCP's verification also binds. Use `attest()`
   * in both cases.
   */
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
    return Object.freeze(result)
  }

  /**
   * Requests a versioned attestation for the given report data.
   *
   * GPU evidence is not available here: this surface is frozen at the 0.5.11
   * shape. Use `DstackClientV1.attest` or `DstackClientV1.attestGpu`.
   */
  async attest(report_data: string | Buffer | Uint8Array): Promise<AttestResponse> {
    let hex = to_hex(report_data)
    if (hex.length > 128) {
      throw new Error(`Report data is too large, it should be less than 64 bytes.`)
    }
    const payload = JSON.stringify({ report_data: hex })
    const result = await send_rpc_request<{ attestation: string }>(this.endpoint, '/Attest', payload)
    throwOnRpcError(result)
    return Object.freeze({
      __name__: 'AttestResponse',
      attestation: result.attestation as Hex,
    })
  }

  async info(): Promise<InfoResponse<T>> {
    const result = await send_rpc_request<Omit<InfoResponse<TcbInfo>, 'tcb_info'> & { tcb_info: string }>(this.endpoint, '/Info', '{}')
    return Object.freeze({
      ...result,
      tcb_info: JSON.parse(result.tcb_info) as T,
    })
  }

  /**
   * Query the guest-agent version.
   *
   * Returns the version on OS >= 0.5.7.
   * Throws on older OS versions that lack the Version RPC.
   */
  async version(): Promise<VersionResponse> {
    const result = await send_rpc_request<{ version: string, rev: string }>(this.endpoint, '/Version', '{}')
    return Object.freeze({
      ...result,
      __name__: 'VersionResponse',
    })
  }

  async isReachable(): Promise<boolean> {
    try {
      // Use info endpoint to test connectivity with 500ms timeout
      await send_rpc_request(this.endpoint, '/Info', '{}', 500)
      return true
    } catch (error) {
      return false
    }
  }

  /**
   * Emit an event. This extends the event to RTMR3 on TDX platform.
   *
   * Requires dstack OS 0.5.0 or later, and removed in 0.6.0: runtime RTMR3
   * events became system-owned, so a 0.6.0 agent answers every call with an
   * error. It stays here because the frozen surface still carries the method,
   * and the agent's own explanation is more useful than one invented here.
   *
   * @param event The event name
   * @param payload The event data as string or Buffer or Uint8Array
   */
  async emitEvent(event: string, payload: string | Buffer | Uint8Array): Promise<void> {
    if (!event) {
      throw new Error('Event name cannot be empty')
    }

    const hexPayload = to_hex(payload)
    const result = await send_rpc_request(
      this.endpoint,
      '/EmitEvent',
      JSON.stringify({
        event: event,
        payload: hexPayload
      })
    )
    throwOnRpcError(result)
  }

  /**
   * Signs a payload using a derived key.
   * @param algorithm The algorithm to use (e.g., "ed25519", "secp256k1", "secp256k1_prehashed")
   * @param data The data to sign. If algorithm is "secp256k1_prehashed", this must be a 32-byte hash.
   * @returns A SignResponse containing the signature, signature chain, and public key.
   */
  async sign(algorithm: string, data: string | Buffer | Uint8Array): Promise<SignResponse> {
    const hexData = to_hex(data);
    if (algorithm === 'secp256k1_prehashed' && hexData.length !== 64) {
        throw new Error(`Pre-hashed signing requires a 32-byte digest, but received ${hexData.length / 2} bytes`);
    }

    const payload = JSON.stringify({
        algorithm: algorithm,
        data: hexData
    });

    const result = await send_rpc_request<{ signature: string, signature_chain: string[], public_key: string }>(this.endpoint, '/Sign', payload);

    return Object.freeze({
        signature: new Uint8Array(Buffer.from(result.signature, 'hex')),
        signature_chain: result.signature_chain.map(sig => new Uint8Array(Buffer.from(sig, 'hex'))),
        public_key: new Uint8Array(Buffer.from(result.public_key, 'hex')),
        __name__: 'SignResponse',
    });
  }

  /**
   * Verifies a payload signature.
   * @param algorithm The algorithm to use (e.g., "ed25519", "secp256k1", "secp256k1_prehashed")
   * @param data The data that was signed.
   * @param signature The signature to verify.
   * @param publicKey The public key to use for verification.
   * @returns A VerifyResponse indicating if the signature is valid.
   */
  async verify(
    algorithm: string,
    data: string | Buffer | Uint8Array,
    signature: string | Buffer | Uint8Array,
    publicKey: string | Buffer | Uint8Array
  ): Promise<VerifyResponse> {
    const payload = JSON.stringify({
        algorithm: algorithm,
        data: to_hex(data),
        signature: to_hex(signature),
        public_key: to_hex(publicKey)
    });

    const result = await send_rpc_request<{ valid: boolean }>(this.endpoint, '/Verify', payload);
    throwOnRpcError(result)

    return Object.freeze({
        ...result,
        __name__: 'VerifyResponse',
    });
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

/**
 * Client for the pre-0.3 tappd service, kept for applications that still call it.
 *
 * It names `DstackClientV0` rather than the `DstackClient` alias on purpose: the
 * alias points at v1 now, and tappd speaks the v0 wire surface.
 *
 * @deprecated Superseded by `DstackClientV0` in dstack 0.3.0, and by
 * `DstackClientV1` for anything new.
 */
export class TappdClient extends DstackClientV0<TcbInfoV03x> {
  constructor(endpoint: string | undefined = undefined) {
    if (endpoint === undefined) {
      if (process.env.TAPPD_SIMULATOR_ENDPOINT) {
        console.warn(`Using tappd endpoint: ${process.env.TAPPD_SIMULATOR_ENDPOINT}`)
        endpoint = process.env.TAPPD_SIMULATOR_ENDPOINT
      } else {
        // Try paths in order: legacy paths first, then namespaced paths
        const socketPaths = [
          '/var/run/tappd.sock',
          '/run/tappd.sock',
          '/var/run/dstack/tappd.sock',
          '/run/dstack/tappd.sock',
        ]
        endpoint = socketPaths.find(p => fs.existsSync(p)) ?? socketPaths[0]
      }
    }
    console.warn('TappdClient is deprecated, please use DstackClientV0 instead')
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
    return Object.freeze(result)
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
