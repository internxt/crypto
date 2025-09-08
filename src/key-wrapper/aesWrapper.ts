import { KEY_WRAPPING_ALGORITHM, KEY_FORMAT, CONTEXT_WRAPPING, AES_ALGORITHM } from '../constants';
import { deriveKeyFromTwoKeysAndContext } from '../derive-key/core';

/**
 * Converts wrapping key in Uint8Array into CryptoKey
 *
 * @param key - The wrapping key in Uint8Array representation
 * @returns The resulting CryptoKey
 */
export async function importWrappingKey(key: Uint8Array): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey(KEY_FORMAT, key, KEY_WRAPPING_ALGORITHM, false, ['wrapKey', 'unwrapKey']);
  } catch (error) {
    throw new Error('Failed to import wrapping key', { cause: error });
  }
}

/**
 * Derives wrapping key from two secrets
 *
 * @param eccSecret - The secret exchanged via elliptic curves
 * @param kyberSecret - The secret exchanged via Kyber KEM
 * @returns The resulting wrapping CryptoKey
 */
export async function deriveWrappingKey(eccSecret: Uint8Array, kyberSecret: Uint8Array): Promise<CryptoKey> {
  try {
    if (eccSecret.length !== kyberSecret.length) {
      throw new Error('secrets must have equal length');
    }
    const key = await deriveKeyFromTwoKeysAndContext(eccSecret, kyberSecret, CONTEXT_WRAPPING);
    return await importWrappingKey(key);
  } catch (error) {
    throw new Error('Failed to derive wrapping key', { cause: error });
  }
}

/**
 * Unwraps the given wrapped key
 *
 * @param encryptedKey - The encrypted key
 * @param wrappingKey - The secret key used for decryption
 * @returns The resulting wrapping CryptoKey
 */
export async function unwrapKey(encryptedKey: Uint8Array, wrappingKey: CryptoKey): Promise<CryptoKey> {
  try {
    return await crypto.subtle.unwrapKey(
      KEY_FORMAT,
      encryptedKey,
      wrappingKey,
      KEY_WRAPPING_ALGORITHM,
      AES_ALGORITHM,
      false,
      ['encrypt', 'decrypt'],
    );
  } catch (error) {
    throw new Error('Failed to unwrap key', { cause: error });
  }
}

/**
 * Wraps the given CryptoKey
 *
 * @param encryptionKey - The CryptoKey to be wrapped
 * @param wrappingKey - The secret key used for wrapping
 * @returns The resulting ciphertext
 */
export async function wrapKey(encryptionKey: CryptoKey, wrappingKey: CryptoKey): Promise<Uint8Array> {
  try {
    const result = await crypto.subtle.wrapKey(KEY_FORMAT, encryptionKey, wrappingKey, KEY_WRAPPING_ALGORITHM);
    return new Uint8Array(result);
  } catch (error) {
    throw new Error('Failed to wrap key', { cause: error });
  }
}
