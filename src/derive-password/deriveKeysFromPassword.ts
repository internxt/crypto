import { argon2, sampleSalt } from './core';

/**
 * Derives a symmetric key from a user's password with a randomly sampled salt
 *
 * @param password - The user's password
 * @returns The derived secret key and randomly sampled salt
 */
export async function getKeyFromPassword(password: string): Promise<{ key: Uint8Array; salt: Uint8Array }> {
  try {
    const salt = sampleSalt();
    const key = await argon2(password, salt);
    return { key, salt };
  } catch (error) {
    throw new Error('Failed to derive key from password', { cause: error });
  }
}

/**
 * Derives a symmetric key from a user's password and salt
 *
 * @param password - The user's password
 * @param salt - The given salt
 * @returns The derived secret key
 */
export async function getKeyFromPasswordAndSalt(password: string, salt: Uint8Array): Promise<Uint8Array> {
  try {
    return await argon2(password, salt);
  } catch (error) {
    throw new Error('Failed to derive key from password and salt', { cause: error });
  }
}
