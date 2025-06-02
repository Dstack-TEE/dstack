import * as CryptoJS from 'crypto-js';
import { isEmpty } from 'lodash';
import { sign_detached, sign_keyPair_fromSeed } from 'tweetnacl-ts/es/sign';

class CoboV2Custody {
  privateKey: string;

  constructor(privateKey: string) {
    this.privateKey = privateKey;
  }

  public sign(message: string) {
    const publicKey = this.getPublicKey();
    const privateKeyBytes = new Uint8Array(Buffer.from(this.privateKey + publicKey, 'hex'));
    const messageBytes = new Uint8Array(Buffer.from(message, 'hex'));
    const signature = sign_detached(messageBytes, privateKeyBytes);
    return Buffer.from(signature).toString('hex');
  }

  public getPublicKey() {
    const privateKeyBytes = new Uint8Array(Buffer.from(this.privateKey, 'hex'));
    const publicKey = sign_keyPair_fromSeed(privateKeyBytes).publicKey;
    return Buffer.from(publicKey).toString('hex');
  }
}

type CoboV2CustodyKeys = {
  'Biz-Api-Key': string;
  'Biz-Api-Nonce': string;
  'Biz-Api-Signature': string;
};

export function getCoboV2CustodyGeneratedKeys(
  secretKey: string,
  method: string | undefined,
  path: string,
  body: unknown,
  query: Record<string, unknown>
): CoboV2CustodyKeys {
  const nonce = String(new Date().getTime());
  const queryString = Object.entries(query)
    .map(([key, value]) => {
      if (typeof value !== 'number' && typeof value !== 'boolean' && typeof value !== 'string')
        return;
      return `${key}=${encodeURIComponent(value)}`;
    })
    .join('&');

  const strToSign = [
    method?.toUpperCase(),
    `/v2${path}`,
    nonce,
    queryString,
    isEmpty(body) ? '' : JSON.stringify(body),
  ].join('|');

  const hash2String = CryptoJS.SHA256(CryptoJS.SHA256(strToSign)).toString();

  const coboV2Custody = new CoboV2Custody(secretKey);

  return {
    'Biz-Api-Key': coboV2Custody.getPublicKey(),
    'Biz-Api-Nonce': nonce,
    'Biz-Api-Signature': coboV2Custody.sign(hash2String),
  };
}
