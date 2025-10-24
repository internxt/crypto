import { AES_ALGORITHM, AES_KEY_BIT_LENGTH, KEY_FORMAT } from '../constants';
import { getBitsFromString } from '../hash';

/**
 * Converts Uint8Array into CryptoKey
 *
 * @param keyData - The Uint8Array representation of the symmetric key
 * @returns The resulting symmetric CryptoKey.
 */
export async function importSymmetricCryptoKey(keyData: Uint8Array | ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    KEY_FORMAT,
    new Uint8Array(keyData),
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
    throw new Error('Failed to export symmetric CryptoKey', { cause: error });
  }
}

/**
 * Generates symmetric CryptoKey
 *
 * @returns The generated CryptoKey.
 */
export async function genSymmetricCryptoKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
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
    crypto.getRandomValues(key);
    return key;
  } catch (error) {
    throw new Error('Failed to generate symmetric key', { cause: error });
  }
}

/**
 * Derives CryptoKey from the given key material
 *
 * @returns The derived CryptoKey.
 */
export async function deriveSymmetricCryptoKey(keyMaterial: string): Promise<CryptoKey> {
  try {
    const hashBuffer = await getBitsFromString(AES_KEY_BIT_LENGTH, keyMaterial);
    return importSymmetricCryptoKey(hashBuffer);
  } catch (error) {
    throw new Error('Failed to derive CryptoKey from the given key material', { cause: error });
  }
}
