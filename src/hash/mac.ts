import { bytesToHex } from '@noble/hashes/utils.js';
import { AES_KEY_BIT_LENGTH } from '../constants';
import { getBytesFromString, keyedHash } from './blake3';

/**
 * Computes mac for the given key material and data
 *
 * @param keyMaterial - The key material
 * @param data - The data to hash
 * @returns The resulting hash hex string
 */
export function computeMac(keyMaterial: string, data: Uint8Array[]): string {
  try {
    const key = getBytesFromString(AES_KEY_BIT_LENGTH / 8, keyMaterial);
    const hash = keyedHash(key, data);
    return bytesToHex(hash);
  } catch (error) {
    throw new Error('Failed to compute mac', { cause: error });
  }
}
