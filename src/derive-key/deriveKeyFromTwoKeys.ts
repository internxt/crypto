import { AES_KEY_BIT_LENGTH, HASH_BIT_LEN } from '../constants';
import { blake3 } from 'hash-wasm';
import { deriveSymmetricKeyFromContext } from './deriveKeysFromKey';
import { importSymmetricCryptoKey } from '../symmetric-crypto';

/**
 * Derives a symmetric key from two keys
 *
 * @param key1 - The 32-bytes key
 * @param key2 - The 32-bytes key
 * @param context - The context string
 * @returns The derived secret key
 */
export async function deriveSymmetricKeyFromTwoKeys(
  key1: Uint8Array,
  key2: Uint8Array,
  context: string,
): Promise<Uint8Array> {
  try {
    if (key2.length != AES_KEY_BIT_LENGTH / 8 || key1.length != AES_KEY_BIT_LENGTH / 8) {
      throw new Error(`Input key length must be exactly ${AES_KEY_BIT_LENGTH / 8} bytes`);
    }
    const combined_key = await blake3(key1, HASH_BIT_LEN, key2);
    const result = await deriveSymmetricKeyFromContext(context, combined_key);
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to derive symmetric key from two keys: ${errorMessage}`));
  }
}

/**
 * Derives a symmetric CryptoKey from two keys
 *
 * @param key1 - The 32-bytes key
 * @param key2 - The 32-bytes key
 * @param context - The context string
 * @returns The derived secret CryptoKey
 */
export async function deriveSymmetricCryptoKeyFromTwoKeys(
  key1: Uint8Array,
  key2: Uint8Array,
  context: string,
): Promise<CryptoKey> {
  try {
    const keyBytes = await deriveSymmetricKeyFromTwoKeys(key1, key2, context);
    const key = await importSymmetricCryptoKey(keyBytes);
    return key;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to derive symmetric CryptoKey from two keys: ${errorMessage}`));
  }
}
