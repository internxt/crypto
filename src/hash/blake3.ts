import { blake3 } from '@noble/hashes/blake3.js';
import { utf8ToBytes, bytesToHex } from '@noble/hashes/utils.js';

/**
 * Hashes the given array of data
 *
 * @param data - The data to hash
 * @returns The resulting hash array
 */
export function hashData(data: Uint8Array[]): Uint8Array {
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

export function keyedHashHex(hashKey: Uint8Array, data: Uint8Array[]): string {
  try {
    const hash = keyedHash(hashKey, data);
    return bytesToHex(hash);
  } catch (error) {
    throw new Error('Failed to compute hash hex', { cause: error });
  }
}

export function keyedHash(hashKey: Uint8Array, data: Uint8Array[]): Uint8Array {
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
 * Hashes the given array of data
 *
 * @param data - The data to hash
 * @returns The resulting hash hex string
 */
export function hashDataHex(data: Uint8Array[]): string {
  try {
    const hash = hashData(data);
    return bytesToHex(hash);
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
export function getBytesFromData(bytes: number, data: Uint8Array[]): Uint8Array {
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
export function getBytesFromDataHex(bytes: number, data: Uint8Array[]): string {
  try {
    const hash = getBytesFromData(bytes, data);
    return bytesToHex(hash);
  } catch (error) {
    throw new Error('Failed to get bytes from data', { cause: error });
  }
}

/**
 * Hashes the given string using blake3 algorithm
 *
 * @param bytes - The desired output byte-length
 * @param value - The string to hash
 * @returns The resulting hash value
 */
export function getBytesFromString(bytes: number, value: string): Uint8Array {
  return blake3(utf8ToBytes(value), { dkLen: bytes });
}

/**
 * Hashes the given string using blake3 algorithm
 *
 * @param bytes - The desired output byte-length
 * @param value - The string to hash
 * @returns The resulting hash value
 */
export function getBytesFromStrinHex(bytes: number, value: string): string {
  return bytesToHex(getBytesFromString(bytes, value));
}
