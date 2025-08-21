import { argon2id } from 'hash-wasm';
import {
  ARGON2ID_ITERATIONS,
  ARGON2ID_MEMORY_SIZE,
  ARGON2ID_PARALLELISM,
  ARGON2ID_SALT_BYTE_LENGTH,
  ARGON2ID_OUTPUT_BYTE_LENGTH,
} from '../utils/constants';

/**
 * Calculates hash using the argon2id password-hashing function
 * @param password - The user's password
 * @param salt - The given salt
 * @param parallelism - The degree of parallelism
 * @param iterations - The number of iterations
 * @param memorySize - The memory size in KB
 * @param hashLength - The desired hash byte length
 * @returns The resulting hash
 */
export async function argon2(
  password: string,
  salt: Uint8Array,
  parallelism: number = ARGON2ID_PARALLELISM,
  iterations: number = ARGON2ID_ITERATIONS,
  memorySize: number = ARGON2ID_MEMORY_SIZE,
  hashLength: number = ARGON2ID_OUTPUT_BYTE_LENGTH,
): Promise<Uint8Array> {
  return argon2id({
    password,
    salt,
    parallelism,
    iterations,
    memorySize,
    hashLength,
    outputType: 'binary',
  });
}

/**
 * Samples a salt
 * @returns The salt
 */
export function sampleSalt(): Uint8Array {
  try {
    const salt = new Uint8Array(ARGON2ID_SALT_BYTE_LENGTH);
    window.crypto.getRandomValues(salt);
    return salt;
  } catch (error) {
    throw new Error('Failed to sample salt:', error);
  }
}
