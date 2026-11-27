// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";

type SortableValue = string | number | boolean | null | undefined | SortableObject | SortableArray;
interface SortableObject {
  [key: string]: SortableValue;
}
interface SortableArray extends Array<SortableValue> {}

export type KeyProviderKind = "none" | "kms" | "local" | "tpm" | "sev-snp";
export type RequirementPlatform =
  | "dstack-tdx"
  | "dstack-gcp-tdx"
  | "dstack-amd-sev-snp"
  | "dstack-nitro-enclave";

export interface DockerConfig extends SortableObject {
  registry?: string | null;
  username?: string | null;
  token_key?: string | null;
}

export interface GpuPolicy extends SortableObject {
  attest_gpu?: boolean;
  rego?: string | null;
  allow_devtools?: boolean;
  allow_debug?: boolean;
  allow_insecure_boot?: boolean;
}

export interface Requirements extends SortableObject {
  platforms?: RequirementPlatform[] | null;
  tdx_measure_acpi_tables?: boolean | null;
  launch_token_hash?: string | null;
  /** Opt-in gateway health gating. A false value is omitted when hashing. */
  health_check?: boolean;
  /**
   * Path to a file the app writes its own verdict into. `""` and absent are
   * different app composes and hash differently, in every SDK.
   */
  health_status_file?: string | null;
  /** Format the data disk on every boot. A false value is omitted when hashing. */
  ephemeral_data_disk?: boolean;
  /** Allow re-keying a data disk left at older key epochs. A false value is omitted when hashing. */
  unsafe_allow_disk_migration?: boolean;
  gpu_policy?: GpuPolicy;
}

export interface PortAttrs extends SortableObject {
  port: number;
  pp?: boolean;
}

export interface PortPolicy extends SortableObject {
  ports?: PortAttrs[];
  restrict_mode?: boolean;
}

export interface VerityVolume extends SortableObject {
  source: string;
  /** dm-verity root hash, hex encoded. */
  verity_root: string;
  target: string;
}

export interface AppCompose extends SortableObject {
  manifest_version?: number | string;
  name?: string;
  // Deprecated
  features?: string[];
  runner: string;
  snapshotter?: "overlayfs" | "stargz" | null;
  docker_compose_file?: string | null;
  docker_config?: DockerConfig;
  public_logs?: boolean;
  public_sysinfo?: boolean;
  public_tcbinfo?: boolean;
  kms_enabled?: boolean;
  gateway_enabled?: boolean;
  // For backward compatibility with tproxy_enabled
  tproxy_enabled?: boolean;
  local_key_provider_enabled?: boolean;
  key_provider?: KeyProviderKind | null;
  key_provider_id?: string; // hex string
  allowed_envs?: string[];
  no_instance_id?: boolean;
  secure_time?: boolean;
  requirements?: Requirements | null;
  init_script?: string | string[] | null;
  storage_fs?: string | null;
  /** Reclaim unused data-disk blocks; disable to hide allocation changes. */
  storage_discard?: boolean;
  /** Size in bytes or a human-readable string, e.g. "2G". */
  swap_size?: number | string;
  event_log_version?: number;
  port_policy?: PortPolicy;
  verity_volumes?: VerityVolume[];
  // Legacy fields for backward compatibility
  bash_script?: string;
  pre_launch_script?: string;
}

function preprocessAppCompose(dic: AppCompose): AppCompose {
  const obj: AppCompose = { ...dic };
  if (obj.runner === "bash" && "docker_compose_file" in obj) {
    delete obj.docker_compose_file;
  } else if ((obj.runner === "docker-compose" || obj.runner === "nerdctl-compose") && "bash_script" in obj) {
    delete obj.bash_script;
  }
  if ("pre_launch_script" in obj && !obj.pre_launch_script) {
    delete obj.pre_launch_script;
  }
  return obj;
}

// Emit entries directly: JSON.stringify on a sorted object would still move
// integer-like keys to the front in numeric order ("2" before "10").
function toDeterministicJson(value: SortableValue): string {
  if (Array.isArray(value)) {
    return '[' + Array.from(value, toDeterministicJson).join(',') + ']';
  }
  if (value !== null && typeof value === 'object') {
    const fields = Object.keys(value).sort()
      .filter(key => value[key] !== undefined)
      .map(key => JSON.stringify(key) + ':' + toDeterministicJson(value[key]));
    return '{' + fields.join(',') + '}';
  }
  return JSON.stringify(value ?? null);
}

function serializeFields(appCompose: AppCompose): AppCompose {
  const result = { ...appCompose };
  for (const field of ['snapshotter', 'requirements', 'init_script']) {
    if (result[field] === null) delete result[field];
  }
  if (result.requirements && typeof result.requirements === 'object' && !Array.isArray(result.requirements)) {
    const requirements = { ...result.requirements };
    for (const field of ['platforms', 'tdx_measure_acpi_tables', 'launch_token_hash', 'health_status_file']) {
      if (requirements[field] === null) delete requirements[field];
    }
    for (const field of ['health_check', 'ephemeral_data_disk', 'unsafe_allow_disk_migration']) {
      if (requirements[field] === false) delete requirements[field];
    }
    if (requirements.gpu_policy && typeof requirements.gpu_policy === 'object' && !Array.isArray(requirements.gpu_policy)) {
      const gpuPolicy = { ...requirements.gpu_policy };
      if (gpuPolicy.rego === null) delete gpuPolicy.rego;
      requirements.gpu_policy = gpuPolicy;
    }
    result.requirements = requirements;
  }
  return result;
}

/**
 * Hash the SDK's compact, sorted JSON representation, not a Rust round-trip.
 * Apart from the documented field omissions and optional normalization, input
 * presence and form are preserved: no Rust defaults are added, empty arrays
 * remain, and init_script retains its string or array form. This matches the
 * deployed hash only when the exact serialized bytes are deployed.
 *
 * Numeric values beyond 2^53 can lose precision in Go and JavaScript. Python
 * serializes a float such as 2.0 as `2.0`, while Go and JavaScript emit `2`.
 */
export function getComposeHash(app_compose: AppCompose, normalize: boolean = false): string {
  app_compose = serializeFields(app_compose);
  if (normalize) {
    app_compose = preprocessAppCompose(app_compose);
  }
  const manifest_str = toDeterministicJson(app_compose);
  return bytesToHex(sha256(new TextEncoder().encode(manifest_str)));
}
