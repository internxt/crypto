import { computeHash } from './core';
import { HASH_BIT_LEN } from '../constants';

/**
 * Hashes the given array of data
 *
 * @param data - The data to hash
 * @returns The resulting hash hex string
 */
export async function hashData(data: string[] | Uint8Array[]): Promise<string> {
  try {
    const hasher = await computeHash(HASH_BIT_LEN, data);
    return hasher.digest();
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to compute hash: ${errorMessage}`);
  }
}

/**
 * Hashes the given array of data using blake3 algorithm
 *
 * @param bits - The desired output bit-length, must be multiple of 8
 * @param data - The data to hash
 * @returns The resulting hash value
 */
export async function getBitsFromData(bits: number, data: string[] | Uint8Array[]): Promise<Uint8Array> {
  try {
    const hasher = await computeHash(bits, data);
    return hasher.digest('binary');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to get bits from data: ${errorMessage}`);
  }
}

/**
 * Hashes the given string using blake3 algorithm
 *
 * @param bits - The desired output bit-length, must be multiple of 8
 * @param value - The string to hash
 * @returns The resulting hash value
 */
export async function getBitsFromString(bits: number, value: string): Promise<Uint8Array> {
  try {
    const hasher = await computeHash(bits, [value]);
    return hasher.digest('binary');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to get bits from string: ${errorMessage}`);
  }
}
