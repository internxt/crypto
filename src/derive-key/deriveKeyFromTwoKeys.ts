import { CONTEXT_DERIVE } from '../constants';
import { deriveKeyFromTwoKeysAndContext } from './core';

import { importSymmetricCryptoKey } from '../symmetric-crypto';

/**
 * Derives a symmetric key from two keys
 *
 * @param key1 - The 32-bytes key
 * @param key2 - The 32-bytes key
 * @returns The derived secret key
 */
export async function deriveSymmetricKeyFromTwoKeys(key1: Uint8Array, key2: Uint8Array): Promise<Uint8Array> {
  return await deriveKeyFromTwoKeysAndContext(key1, key2, CONTEXT_DERIVE);
}

/**
 * Derives a symmetric CryptoKey from two keys
 *
 * @param key1 - The 32-bytes key
 * @param key2 - The 32-bytes key
 * @returns The derived secret CryptoKey
 */
export async function deriveSymmetricCryptoKeyFromTwoKeys(key1: Uint8Array, key2: Uint8Array): Promise<CryptoKey> {
  try {
    const keyBytes = await deriveSymmetricKeyFromTwoKeys(key1, key2);
    const key = await importSymmetricCryptoKey(keyBytes);
    return key;
  } catch (error) {
    throw new Error('Failed to derive symmetric CryptoKey from two keys', { cause: error });
  }
}
