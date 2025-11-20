import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '@noble/hashes/utils.js';

/**
 * Hashes the given array of data
 *
 * @param data - The data to hash
 * @returns The resulting hash array
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
 * Hashes the given array of data
 *
 * @param data - The data to hash
 * @returns The resulting hash hex string
 */
export function hashDataArrayHex(data: Uint8Array[]): string {
  return bytesToHex(hashDataArray(data));
}

export function hashDataArrayWithKeyHex(hashKey: Uint8Array, data: Uint8Array[]): string {
  try {
    const hash = hashDataArrayWithKey(hashKey, data);
    return bytesToHex(hash);
  } catch (error) {
    throw new Error('Failed to compute hash hex', { cause: error });
  }
}

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
 * Hashes the given array of data using blake3 algorithm
 *
 * @param bytes - The desired output byte-length
 * @param data - The data to hash
 * @returns The resulting hash value
 */
export function getBytesFromDataArray(bytes: number, data: Uint8Array[]): Uint8Array {
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
 * Hashes the given array of data using blake3 algorithm
 *
 * @param bytes - The desired output byte-length
 * @param data - The data to hash
 * @returns The resulting hash value
 */
export function getBytesFromDataArrayHex(bytes: number, data: Uint8Array[]): string {
  try {
    const hash = getBytesFromDataArray(bytes, data);
    return bytesToHex(hash);
  } catch (error) {
    throw new Error('Failed to get bytes from data', { cause: error });
  }
}

/**
 * Hashes the given string using blake3 algorithm
 *
 * @param bytes - The desired output byte-length
 * @param data - The data to hash
 * @returns The resulting hash value
 */
export function getBytesFromData(bytes: number, data: Uint8Array): Uint8Array {
  return blake3(data, { dkLen: bytes });
}

/**
 * Hashes the given data using blake3 algorithm
 *
 * @param bytes - The desired output byte-length
 * @param data - The data to hash
 * @returns The resulting hash value
 */
export function getBytesFromDataHex(bytes: number, data: Uint8Array): string {
  return bytesToHex(getBytesFromData(bytes, data));
}
