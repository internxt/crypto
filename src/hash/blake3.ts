import { blake3 } from '@noble/hashes/blake3.js';

/**
 * Hashes the given array of data
 *
 * @param data - The array of data
 * @returns The resulting hash
 */
export function hashDataArray(data: Uint8Array[]): Uint8Array {
  try {
    const hasher = blake3.create();
    for (const d of data) {
      hasher.update(d);
    }
    return hasher.digest();
  } catch (error) {
    throw new Error('Failed to compute hash', { cause: error });
  }
}

/**
 * Hashes the given array of data with the given key
 *
 * @param hashKey - The key for keyed hashing
 * @param data - The array of data
 * @returns The resulting keyed hash
 */
export function hashDataArrayWithKey(hashKey: Uint8Array, data: Uint8Array[]): Uint8Array {
  try {
    const hasher = blake3.create({ key: hashKey });
    for (const d of data) {
      hasher.update(d);
    }
    return hasher.digest();
  } catch (error) {
    throw new Error('Failed to compute hash', { cause: error });
  }
}

/**
 * Hashes the given array of data to the desired byte-length
 *
 * @param data - The array of data
 * @param bytes - The desired output byte-length
 * @returns The resulting hash of the desired byte-length
 */
export function getBytesFromDataArray(data: Uint8Array[], bytes: number): Uint8Array {
  try {
    const hasher = blake3.create({ dkLen: bytes });
    for (const chunk of data) {
      hasher.update(chunk);
    }
    return hasher.digest();
  } catch (error) {
    throw new Error('Failed to get bytes from data', { cause: error });
  }
}

/**
 * Hashes the given data
 *
 * @param data - The data
 * @returns The resulting hash
 */
export function hashData(data: Uint8Array): Uint8Array {
  return blake3(data);
}

/**
 * Hashes the given data with the given key
 *
 * @param hashKey - The key for keyed hashing
 * @param data - The data
 * @returns The resulting keyed hash
 */
export function hashDataWithKey(hashKey: Uint8Array, data: Uint8Array): Uint8Array {
  return blake3(data, { key: hashKey });
}

/**
 * Hashes the given data to the desired byte-length
 *
 * @param data - The data
 * @param bytes - The desired output byte-length
 * @returns The resulting hash of the desired byte-length
 */
export function getBytesFromData(data: Uint8Array, bytes: number): Uint8Array {
  return blake3(data, { dkLen: bytes });
}
