import { blake3 } from 'hash-wasm';
import { AES_KEY_BIT_LENGTH } from '../constants';
import { hexToUint8Array } from '../utils';
import { importSymmetricCryptoKey } from '../symmetric-crypto';

/**
 * Derives a symmetric key from the base key and context string
 *
 * @param context - The context string.
 * The context string should be hardcoded, globally unique, and application-specific.
 * @param baseKey - The base key (NOT PASSWORD!)
 * @returns The derived secret key
 */
export async function deriveSymmetricKeyFromContext(
  context: string,
  baseKey: Uint8Array | string,
): Promise<Uint8Array> {
  try {
    const context_key = await blake3(context);
    const buffer_context_key = hexToUint8Array(context_key);
    const result = await blake3(baseKey, AES_KEY_BIT_LENGTH, buffer_context_key);
    return hexToUint8Array(result);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to derive key from base key and context: ${errorMessage}`));
  }
}

/**
 * Derives a symmetric CryptoKey from the base key and context string
 *
 * @param context - The context string.
 * The context string should be hardcoded, globally unique, and application-specific.
 * @param baseKey - The base key (NOT PASSWORD!)
 * @returns The derived secret CryptoKey
 */
export async function deriveSymmetricCryptoKeyFromContext(context: string, baseKey: Uint8Array): Promise<CryptoKey> {
  try {
    if (baseKey.length != AES_KEY_BIT_LENGTH / 8) {
      throw new Error(`Base key length must be exactly ${AES_KEY_BIT_LENGTH / 8} bytes`);
    }
    if (!context) {
      throw new Error('Context is empry');
    }
    const keyBytes = await deriveSymmetricKeyFromContext(context, baseKey);
    const key = await importSymmetricCryptoKey(keyBytes);

    return key;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to derive CryptoKey from base key and context: ${errorMessage}`));
  }
}
