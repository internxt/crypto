import { bytesToHex } from '@noble/hashes/utils.js';
import { AES_KEY_BYTE_LENGTH } from '../constants';
import { getBytesFromData, hashDataArrayWithKey } from './blake3';

/**
 * Computes mac for the given key material and data
 *
 * @param keyMaterial - The key material
 * @param data - The data to hash
 * @returns The resulting hash hex string
 */
export function computeMac(keyMaterial: Uint8Array, data: Uint8Array[]): string {
  try {
    const key = getBytesFromData(AES_KEY_BYTE_LENGTH, keyMaterial);
    const hash = hashDataArrayWithKey(key, data);
    return bytesToHex(hash);
  } catch (error) {
    throw new Error('Failed to compute mac', { cause: error });
  }
}
