// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

type SortableValue = string | number | boolean | null | undefined | SortableObject | SortableArray;
interface SortableObject {
  [key: string]: SortableValue;
}
interface SortableArray extends Array<SortableValue> {}

/**
 * Recursively sorts object keys lexicographically.
 * @param obj - The object to sort
 * @returns A new object with sorted keys
 */
function sortObjectKeys(obj: SortableValue): SortableValue {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sortObjectKeys);
  
  const sortedObj: SortableObject = {};
  Object.keys(obj).sort().forEach(key => {
    sortedObj[key] = sortObjectKeys((obj as SortableObject)[key]);
  });
  return sortedObj;
}

async function sha256Hash(data: string): Promise<string> {
  return bytesToHex(sha256(new TextEncoder().encode(data)));
}

/**
 * Get the hash of a docker-compose configuration
 * @param compose - The docker-compose configuration object
 * @returns Promise resolving to hex-encoded hash
 */
export async function getComposeHash(compose: Record<string, any>): Promise<string> {
  // Sort the object keys to ensure deterministic hashing
  const sortedCompose = sortObjectKeys(compose);
  
  // Convert to JSON string with no extra whitespace
  const jsonString = JSON.stringify(sortedCompose);
  
  // Return SHA-256 hash
  return sha256Hash(jsonString);
}