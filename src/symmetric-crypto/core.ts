import { randomBytes } from '@noble/post-quantum/utils.js';
import { IV_LENGTH, AUX_LEN, NONCE_LENGTH } from '../utils';
import { getHash } from '../hash';

export function createIV(n: number): Uint8Array {
  try {
    const MAX_NONCE_VALUE = Math.pow(2, NONCE_LENGTH * 8);
    const randLen = IV_LENGTH - NONCE_LENGTH;
    const rand = randomBytes(randLen);
    const iv = new Uint8Array(IV_LENGTH);
    iv.set(rand, 0);

    const view = new DataView(iv.buffer, randLen, NONCE_LENGTH);
    view.setUint32(0, n % MAX_NONCE_VALUE);

    return new Uint8Array(iv);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to create IV: ${errorMessage}`);
  }
}

export async function genAuxFromParams(parameters: string[]): Promise<Uint8Array> {
  return getHash(AUX_LEN, parameters);
}
