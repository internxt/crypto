import { blake3 } from '@noble/hashes/blake3.js';
import { AES_KEY_BIT_LENGTH, CONTEXT_DERIVE } from '../constants';
import { UTF8ToUint8 } from '../utils';

/**
 * Derives a symmetric key from the base key and context string
 *
 * @param context - The context string.
 * The context string should be hardcoded, globally unique, and application-specific.
 * @param baseKey - The base key (NOT PASSWORD!)
 * @returns The derived secret key
 */
export function deriveSymmetricKeyFromContext(context: string, baseKey: Uint8Array): Uint8Array {
  return blake3(baseKey, { context: UTF8ToUint8(context) });
}

/**
 * Derives a symmetric key from two keys
 *
 * @param key1 - The 32-bytes key
 * @param key2 - The 32-bytes key
 * @returns The derived secret key
 */
export function deriveSymmetricKeyFromTwoKeys(key1: Uint8Array, key2: Uint8Array): Uint8Array {
  return deriveSymmetricKeyFromTwoKeysAndContext(key1, key2, CONTEXT_DERIVE);
}

/**
 * Derives a symmetric key from two keys and context
 *
 * @param key1 - The 32-bytes key
 * @param key2 - The 32-bytes key
 * @param context - The context string
 * @returns The derived symmetric key
 */
export function deriveSymmetricKeyFromTwoKeysAndContext(
  key1: Uint8Array,
  key2: Uint8Array,
  context: string,
): Uint8Array {
  try {
    if (key2.length != AES_KEY_BIT_LENGTH / 8 || key1.length != AES_KEY_BIT_LENGTH / 8) {
      throw new Error(`Input key length must be exactly ${AES_KEY_BIT_LENGTH / 8} bytes`);
    }
    const key = blake3(key1, { key: key2 });
    return blake3(key, { context: UTF8ToUint8(context) });
  } catch (error) {
    throw new Error('Failed to derive symmetric key from two keys and context', { cause: error });
  }
}
