import { randomBytes } from '@noble/post-quantum/utils.js';
import { IV_LENGTH, AUX_LEN, NONCE_LENGTH } from '../utils/constants';
import { getHash } from '../hash/blake3';
import { SymmetricCiphertext } from '../utils/types';
import { uint8ArrayToBase64, decodeBase64, base64ToUint8Array } from '../utils/converters';

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

export function ciphertextToBase64(cipher: SymmetricCiphertext): string {
  try {
    const ivBase64 = uint8ArrayToBase64(cipher.iv);
    const ciphertextBase64 = uint8ArrayToBase64(cipher.ciphertext);
    const json = JSON.stringify({ ciphertext: ciphertextBase64, iv: ivBase64 });
    const base64 = btoa(json);
    return base64;
  } catch (error) {
    throw new Error(`Cannot convert ciphertext to base64: ${error}`);
  }
}

export function base64ToCiphertext(base64: string): SymmetricCiphertext {
  try {
    const json = decodeBase64(base64);
    const obj = JSON.parse(json);
    const iv = base64ToUint8Array(obj.iv);
    const ciphertext = base64ToUint8Array(obj.ciphertext);
    const result: SymmetricCiphertext = {
      ciphertext,
      iv,
    };
    return result;
  } catch (error) {
    throw new Error(`Cannot convert base64 to ciphertext: ${error}`);
  }
}
