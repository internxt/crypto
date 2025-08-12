import { Buffer } from 'buffer';

export function arrayToHex(array: Uint8Array): string {
  return Buffer.from(array).toString('hex');
}
