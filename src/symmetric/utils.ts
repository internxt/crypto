import { randomBytes } from '@noble/post-quantum/utils.js';
import { IV_LENGTH, AUX_LEN, NONCE_LENGTH } from '../utils/constants';
import { getHash } from '../hash/blake3';
import { SymmetricCiphertext } from '../utils/types';
import { Buffer } from 'buffer';

const MAX_NONCE_VALUE = Math.pow(2, NONCE_LENGTH * 8);

export function createIV(n: number): Uint8Array {
  const randLen = IV_LENGTH - NONCE_LENGTH;
  const rand = randomBytes(randLen);
  const iv = new Uint8Array(IV_LENGTH);
  iv.set(rand, 0);

  const view = new DataView(iv.buffer, randLen, NONCE_LENGTH);
  view.setUint32(0, n % MAX_NONCE_VALUE);

  return new Uint8Array(iv);
}

export async function genAuxFromParams(parameters: string[]): Promise<Uint8Array> {
  const aux = await getHash(AUX_LEN, parameters);
  return aux;
}

export function ciphertextToBase64(ciphertext: SymmetricCiphertext): string {
  try {
    const json = JSON.stringify(ciphertext);
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    throw new Error(`Cannot convert ciphertext to base64: ${error}`);
  }
}

export function base64ToCiphertext(ciphertext: string): SymmetricCiphertext {
  try {
    const json = Buffer.from(ciphertext, 'base64').toString('utf-8');
    const result: SymmetricCiphertext = JSON.parse(json);
    return result;
  } catch (error) {
    throw new Error(`Cannot convert base64 to ciphertext: ${error}`);
  }
}
