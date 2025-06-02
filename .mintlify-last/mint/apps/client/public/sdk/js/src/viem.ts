import { type GetKeyResponse } from './index'
import { privateKeyToAccount } from 'viem/accounts'

export function toViemAccount(keyResponse: GetKeyResponse) {
  const hex = Array.from(keyResponse.key).map(b => b.toString(16).padStart(2, '0')).join('')
  return privateKeyToAccount(`0x${hex}`)
}
