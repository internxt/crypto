import { argon2id, blake3 } from 'hash-wasm';
import {
  AES_KEY_BIT_LENGTH,
  HASH_BIT_LEN,
  ARGON2ID_ITERATIONS,
  ARGON2ID_MEMORY_SIZE,
  ARGON2ID_PARALLELISM,
  ARGON2ID_SALT_BYTE_LENGTH,
  ARGON2ID_OUTPUT_BYTE_LENGTH,
} from '../constants';
import { deriveSymmetricKeyFromContext } from './deriveKeysFromKey';

/**
 * Calculates hash using the argon2id password-hashing function
 *
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
 *
 * @returns The salt
 */
export function sampleSalt(): Uint8Array {
  try {
    const salt = new Uint8Array(ARGON2ID_SALT_BYTE_LENGTH);
    window.crypto.getRandomValues(salt);
    return salt;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to sample salt: ${errorMessage}`);
  }
}

/**
 * Derives a symmetric key from two keys
 *
 * @param key1 - The 32-bytes key
 * @param key2 - The 32-bytes key
 * @returns The derived secret key
 */
export async function deriveKeyFromTwoKeysAndContext(
  key1: Uint8Array,
  key2: Uint8Array,
  context: string,
): Promise<Uint8Array> {
  try {
    if (key2.length != AES_KEY_BIT_LENGTH / 8 || key1.length != AES_KEY_BIT_LENGTH / 8) {
      throw new Error(`Input key length must be exactly ${AES_KEY_BIT_LENGTH / 8} bytes`);
    }
    const combined_key = await blake3(key1, HASH_BIT_LEN, key2);
    const result = await deriveSymmetricKeyFromContext(context, combined_key);
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to derive symmetric key from two keys: ${errorMessage}`));
  }
}
