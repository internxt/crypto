import { computeKeyedHash } from './core';
import { HASH_BIT_LEN, AES_KEY_BIT_LENGTH } from '../constants';
import { getBitsFromString } from './blake3';

/**
 * Computes mac for the given key material and data
 *
 * @param keyMaterial - The key material
 * @param data - The data to hash
 * @returns The resulting hash hex string
 */
export async function computeMac(keyMaterial: string, data: string[]): Promise<string> {
  try {
    const key = await getBitsFromString(AES_KEY_BIT_LENGTH, keyMaterial);
    const hasher = await computeKeyedHash(HASH_BIT_LEN, key, data);
    return hasher.digest();
  } catch (error) {
    throw new Error('Failed to compute mac', { cause: error });
  }
}
