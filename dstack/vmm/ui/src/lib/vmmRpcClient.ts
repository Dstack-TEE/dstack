// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

const { vmm } = require('../proto/vmm_rpc.js');
const { prpc } = require('../proto/prpc.js');

const textDecoder = new TextDecoder();
const EMPTY_BODY = new Uint8Array();
let cachedClient: any;

function decodePrpcError(buffer: Uint8Array) {
  try {
    if (buffer && buffer.length > 0) {
      const err = prpc.PrpcError.decode(buffer);
      if (err?.message) {
        return err.message;
      }
    }
  } catch {
    // Ignore decode failures; fall through to text decoding.
  }
  try {
    const text = buffer && buffer.length > 0 ? textDecoder.decode(buffer) : '';
    return text || 'Unknown RPC error';
  } catch {
    return 'Unknown RPC error';
  }
}

function normalizeRequestData(data?: Uint8Array | ArrayBuffer | null) {
  if (!data) {
    return EMPTY_BODY;
  }
  if (data instanceof Uint8Array) {
    return data;
  }
  return new Uint8Array(data);
}

function resolveMethodName(method: any) {
  if (!method) {
    return '';
  }
  const type = typeof method;
  if (type === 'string') {
    return method;
  }
  if (type === 'function' || type === 'object') {
    if (method.name) {
      return method.name.charAt(0).toUpperCase() + method.name.slice(1);
    }
    if (method.fullName) {
      const parts = String(method.fullName).split('.');
      return parts[parts.length - 1];
    }
  }
  return String(method);
}

export function getVmmRpcClient(basePath = '/prpc') {
  if (cachedClient) {
    return cachedClient;
  }

  const rpcImpl = (method: any, requestData: Uint8Array, callback: (err?: Error | null, data?: Uint8Array) => void) => {
    const methodName = resolveMethodName(method);
    const payload = normalizeRequestData(requestData);
    fetch(`${basePath}/${methodName}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
      },
      body: payload as unknown as BodyInit,
      credentials: 'same-origin',
    })
      .then(async (response) => {
        const buffer = new Uint8Array(await response.arrayBuffer());
        if (!response.ok) {
          callback(new Error(decodePrpcError(buffer)));
          return;
        }
        callback(null, buffer);
      })
      .catch((error) => {
        callback(error);
      });
  };

  cachedClient = vmm.Vmm.create(rpcImpl, false, false);
  return cachedClient;
}
