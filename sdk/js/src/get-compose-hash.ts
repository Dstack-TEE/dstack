// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import crypto from "crypto";

type SortableValue = string | number | boolean | null | undefined | SortableObject | SortableArray;
interface SortableObject {
  [key: string]: SortableValue;
}
interface SortableArray extends Array<SortableValue> {}

/**
 * Recursively sorts object keys lexicographically.
 * This is crucial for deterministic JSON.stringify in JavaScript.
 * @param obj The object to sort.
 * @returns A new object with sorted keys, or the original value if not an object.
 */
function sortObject(obj: SortableValue): SortableValue {
  if (obj === undefined || obj === null) {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(sortObject);
  } else if (obj && typeof obj === "object" && obj.constructor === Object) {
    return Object.keys(obj)
      .sort()
      .reduce((result: SortableObject, key) => {
        const value = (obj as SortableObject)[key];
        result[key] = sortObject(value);
        return result;
      }, {});
  }
  return obj;
}

export type KeyProviderKind = "none" | "kms" | "local";

export interface DockerConfig extends SortableObject {
  registry?: string;
  username?: string;
  token_key?: string;
}

export interface AppCompose extends SortableObject {
  manifest_version?: number;
  name?: string;
  // Deprecated
  features?: string[];
  runner: string;
  docker_compose_file?: string;
  docker_config?: DockerConfig;
  public_logs?: boolean;
  public_sysinfo?: boolean;
  public_tcbinfo?: boolean;
  kms_enabled?: boolean;
  gateway_enabled?: boolean;
  // For backward compatibility with tproxy_enabled
  tproxy_enabled?: boolean;
  local_key_provider_enabled?: boolean;
  key_provider?: KeyProviderKind;
  key_provider_id?: string; // hex string
  allowed_envs?: string[];
  no_instance_id?: boolean;
  secure_time?: boolean;
  // Legacy fields for backward compatibility
  bash_script?: string;
  pre_launch_script?: string;
}

function preprocessAppCompose(dic: AppCompose): AppCompose {
  const obj: AppCompose = { ...dic };
  if (obj.runner === "bash" && "docker_compose_file" in obj) {
    delete obj.docker_compose_file;
  } else if (obj.runner === "docker-compose" && "bash_script" in obj) {
    delete obj.bash_script;
  }
  if ("pre_launch_script" in obj && !obj.pre_launch_script) {
    delete obj.pre_launch_script;
  }
  return obj;
}

/**
 * Deterministic JSON serialization following cross-language standards.
 * - Recursively sorts object keys lexicographically
 * - Compact output (no spaces)
 * - Handles special values (NaN, Infinity) by converting them to null
 * - UTF-8 encoding (default in JavaScript)
 */
function toDeterministicJson(dic: AppCompose): string {
  const ordered = sortObject(dic);
  return JSON.stringify(ordered, (key, value) => {
    // Convert NaN and Infinity to null for deterministic output
    if (typeof value === 'number' && (isNaN(value) || !isFinite(value))) {
      return null;
    }
    return value;
  }); // Omit the 'space' argument for compact output
}

export function getComposeHash(app_compose: AppCompose, normalize: boolean = false): string {
  if (normalize) {
    app_compose = preprocessAppCompose(app_compose);
  }
  const manifest_str = toDeterministicJson(app_compose);
  return crypto.createHash("sha256").update(manifest_str, "utf8").digest("hex");
}