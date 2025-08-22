import { createBLAKE3 } from 'hash-wasm';

/**
 * Hashes the given array of data using blake3 algorithm
 *
 * @param bits - The desired output bit-length, must be multiple of 8
 * @param data - The data to hash
 * @returns The resulting hash value
 */
export async function getHash(bits: number, data: string[] | Uint8Array[]) {
  try {
    const hasher = await createBLAKE3(bits);
    hasher.init();
    for (const chunk of data) {
      hasher.update(chunk);
    }

    return hasher.digest('binary');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to compute hash: ${errorMessage}`);
  }
}

/**
 * Hashes the given string using blake3 algorithm
 *
 * @param bits - The desired output bit-length, must be multiple of 8
 * @param value - The string to hash
 * @returns The resulting hash value
 */
export async function hashString(bits: number, value: string) {
  try {
    const hasher = await createBLAKE3(bits);
    hasher.init();
    hasher.update(value);
    return hasher.digest('binary');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to hash the given string: ${errorMessage}`);
  }
}
