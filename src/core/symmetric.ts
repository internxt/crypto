import { randomBytes } from '@noble/post-quantum/utils.js';
import { getHash } from './hash';
import {
  AES_ALGORITHM,
  AES_KEY_BIT_LENGTH,
  IV_LENGTH,
  AUX_LEN,
  NONCE_LENGTH,
} from '../utils/constants';

const MAX_NONCE_VALUE = Math.pow(2, NONCE_LENGTH * 8);

export async function generateSymmetricKey(): Promise<CryptoKey> {
  return window.crypto.subtle.generateKey(
    {
      name: AES_ALGORITHM,
      length: AES_KEY_BIT_LENGTH,
    },
    true,
    ['encrypt', 'decrypt'],
  );
}

export function createIV(n: number): Uint8Array {
  const randLen = IV_LENGTH - NONCE_LENGTH;
  const rand = randomBytes(randLen);
  const iv = new Uint8Array(IV_LENGTH);
  iv.set(rand, 0);

  const view = new DataView(iv.buffer, randLen, NONCE_LENGTH);
  view.setUint32(0, n % MAX_NONCE_VALUE);

  return new Uint8Array(iv);
}

export async function encryptSymmetrically(
  encryptionKey: CryptoKey,
  nonce: number,
  message: Uint8Array,
  aux: string,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const iv = createIV(nonce);
  const additionalData = await getHash(AUX_LEN, [AES_ALGORITHM, aux]);
  const encrypted = await window.crypto.subtle.encrypt(
    { name: AES_ALGORITHM, iv, additionalData },
    encryptionKey,
    message,
  );
  const ciphertext = new Uint8Array(encrypted);
  return { ciphertext, iv };
}

export async function decryptSymmetrically(
  encryptionKey: CryptoKey,
  iv: Uint8Array,
  cipherText: Uint8Array,
  aux: string,
): Promise<Uint8Array> {
  const additionalData = await getHash(AUX_LEN, [AES_ALGORITHM, aux]);
  const decrypted = await window.crypto.subtle.decrypt(
    { name: AES_ALGORITHM, iv, additionalData },
    encryptionKey,
    cipherText,
  );
  return new Uint8Array(decrypted);
}
