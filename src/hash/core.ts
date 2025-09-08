import { createBLAKE3, IHasher } from 'hash-wasm';

/**
 * Hashes the given array of data using blake3 algorithm
 *
 * @param bits - The desired output bit-length, must be multiple of 8
 * @param data - The given data to hash
 * @returns The resulting hash value
 */
export async function computeHash(bits: number, data: string[] | Uint8Array[]): Promise<IHasher> {
  try {
    const hasher = await createBLAKE3(bits);
    hasher.init();
    for (const chunk of data) {
      hasher.update(chunk);
    }
    return hasher;
  } catch (error) {
    throw new Error('Failed to compute hash', { cause: error });
  }
}
