import { ec as EC } from 'elliptic';
import sha256 from 'sha256';

import { addTrailingSlashIfNotExists } from './utils';

class CoboCustody {
  privateKey: string;

  constructor(privateKey: string) {
    this.privateKey = privateKey;
  }

  public sign = (message: string) => {
    const privateKey = Buffer.from(this.privateKey, 'hex');
    const secp256k1 = new EC('secp256k1');
    const sig = secp256k1.sign(Buffer.from(sha256.x2(message), 'hex'), privateKey);
    return sig.toDER('hex');
  };

  public getPublicKey = () => {
    try {
      const secp256k1 = new EC('secp256k1');
      const privateKey = Buffer.from(this.privateKey, 'hex');
      const keyPair = secp256k1.keyFromPrivate(privateKey);
      return keyPair.getPublic().encodeCompressed('hex');
    } catch {
      return '';
    }
  };
}

type CoboV1CustodyKeys = {
  'BIZ-API-KEY': string;
  'BIZ-API-SIGNATURE': string;
  'BIZ-API-NONCE': string;
};

export function getCoboV1CustodyGeneratedKeys(
  method: string | undefined,
  path: string,
  key: unknown,
  signatureContent: Record<string, string | number | boolean>
): CoboV1CustodyKeys {
  const coboPrivateKey = typeof key === 'string' ? key : '';
  const nonce = String(new Date().getTime());
  const sortedParams = Object.entries(signatureContent)
    .sort()
    .map(([k, v]) => {
      return k + '=' + encodeURIComponent(v).replace(/%20/g, '+');
    })
    .filter(Boolean)
    .join('&');
  const content = [
    method?.toUpperCase(),
    addTrailingSlashIfNotExists(path),
    nonce,
    sortedParams,
  ].join('|');
  const coboCustody = new CoboCustody(coboPrivateKey);

  return {
    'BIZ-API-KEY': coboCustody.getPublicKey(),
    'BIZ-API-SIGNATURE': coboCustody.sign(content),
    'BIZ-API-NONCE': nonce,
  };
}
