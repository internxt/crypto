import { aeskw } from '@noble/ciphers/aes.js';

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
