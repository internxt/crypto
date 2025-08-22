import { AES_ALGORITHM, AES_KEY_BIT_LENGTH, KEY_FORMAT } from '../utils';

/**
 * Converts Uint8Array into CryptoKey
 *
 * @param keyData - The Uint8Array representation of the symmetric key
 * @returns The resulting symmetric CryptoKey.
 */
export async function importSymmetricCryptoKey(keyData: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    KEY_FORMAT,
    keyData,
    {
      name: AES_ALGORITHM,
      length: AES_KEY_BIT_LENGTH,
    },
    true,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Converts CryptoKey into Uint8Array
 *
 * @param key - The symmetric CryptoKey
 * @returns The resulting Uint8Array.
 */
export async function exportSymmetricCryptoKey(key: CryptoKey): Promise<Uint8Array> {
  try {
    const rawKey = await crypto.subtle.exportKey(KEY_FORMAT, key);
    return new Uint8Array(rawKey);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to export symmetric CryptoKey: ${errorMessage}`));
  }
}

/**
 * Generates symmetric CryptoKey
 *
 * @returns The generated CryptoKey.
 */
export async function genSymmetricCryptoKey(): Promise<CryptoKey> {
  return window.crypto.subtle.generateKey(
    {
      name: AES_ALGORITHM,
      length: AES_KEY_BIT_LENGTH,
    },
    true,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Generates symmetric key as Uint8Array
 *
 * @returns The generated Uint8Array.
 */
export function genSymmetricKey(): Uint8Array {
  try {
    const key = new Uint8Array(AES_KEY_BIT_LENGTH / 8);
    window.crypto.getRandomValues(key);
    return key;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to generate symmetric key: ${errorMessage}`);
  }
}
