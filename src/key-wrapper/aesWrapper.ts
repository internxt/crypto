import { CONTEXT_WRAPPING } from '../constants';
import { deriveSymmetricKeyFromTwoKeysAndContext } from '../derive-key';
import { aeskw } from '@noble/ciphers/aes.js';

/**
 * Derives wrapping key from two secrets
 *
 * @param eccSecret - The secret exchanged via elliptic curves
 * @param kyberSecret - The secret exchanged via Kyber KEM
 * @returns The resulting wrapping key
 */
export async function deriveWrappingKey(eccSecret: Uint8Array, kyberSecret: Uint8Array): Promise<Uint8Array> {
  try {
    if (eccSecret.length !== kyberSecret.length) {
      throw new Error('secrets must have equal length');
    }
    return deriveSymmetricKeyFromTwoKeysAndContext(eccSecret, kyberSecret, CONTEXT_WRAPPING);
  } catch (error) {
    throw new Error('Failed to derive wrapping key', { cause: error });
  }
}

/**
 * Unwraps the given wrapped key
 *
 * @param encryptedKey - The wrapped key
 * @param wrappingKey - The secret key used for unwrapping
 * @returns The resulting key
 */
export async function unwrapKey(encryptedKey: Uint8Array, wrappingKey: Uint8Array): Promise<Uint8Array> {
  return aeskw(wrappingKey).decrypt(encryptedKey);
}

/**
 * Wraps the given key
 *
 * @param key - The key to be wrapped
 * @param wrappingKey - The secret key used for wrapping
 * @returns The resulting ciphertext
 */
export async function wrapKey(key: Uint8Array, wrappingKey: Uint8Array): Promise<Uint8Array> {
  return aeskw(wrappingKey).encrypt(key);
}
