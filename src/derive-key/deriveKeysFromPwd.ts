import { hexToUint8Array, uint8ArrayToHex } from '../utils';
import { argon2, sampleSalt } from './utils';

/**
 * Derives a symmetric key from a user's password with a randomly sampled salt
 * @param password - The user's password
 * @returns The derived secret key and randomly sampled salt
 */
export async function getKeyFromPassword(password: string): Promise<{ key: Uint8Array; salt: Uint8Array }> {
  try {
    if (!password) {
      throw new Error('No password given');
    }
    const salt = sampleSalt();
    const key = await argon2(password, salt);
    return { key, salt };
  } catch (error) {
    return Promise.reject(new Error('Failed to derive key from password', error));
  }
}

/**
 * Derives a symmetric key from a user's password and salt
 * @param password - The user's password
 * @param salt - The given salt
 * @returns The derived secret key
 */
export async function getKeyFromPasswordAndSalt(password: string, salt: Uint8Array): Promise<Uint8Array> {
  try {
    if (!salt.length) {
      throw new Error('No salt given');
    }
    if (!password) {
      throw new Error('No password given');
    }
    return await argon2(password, salt);
  } catch (error) {
    return Promise.reject(new Error('Failed to derive key from password and salt', error));
  }
}

/**
 * Derives a HEX symmetric key from a user's password with a randomly sampled salt
 * @param password - The user's password
 * @returns The derived HEX secret key and randomly sampled HEX salt
 */
export async function getKeyFromPasswordHex(password: string): Promise<{ keyHex: string; saltHex: string }> {
  try {
    const { key, salt } = await getKeyFromPassword(password);
    return { keyHex: uint8ArrayToHex(key), saltHex: uint8ArrayToHex(salt) };
  } catch (error) {
    return Promise.reject(new Error('Failed to derive key from password', error));
  }
}

/**
 * Derives a HEX symmetric key from a user's password and salt
 * @param password - The user's password
 * @param saltHex - The given HEX salt
 * @returns The derived HEX secret key
 */
export async function getKeyFromPasswordAndSaltHex(password: string, saltHex: string): Promise<string> {
  try {
    const salt = hexToUint8Array(saltHex);
    const key = await getKeyFromPasswordAndSalt(password, salt);
    return uint8ArrayToHex(key);
  } catch (error) {
    return Promise.reject(new Error('Failed to derive key from password and salt', error));
  }
}

/**
 * Verifies the derived key
 * @param password - The user's password
 * @param saltHex - The given HEX salt
 * @param keyHex - The derived HEX key
 * @returns The result of the key verification
 */
export async function verifyKeyFromPasswordHex(password: string, saltHex: string, keyHex: string): Promise<boolean> {
  const result = await getKeyFromPasswordAndSaltHex(password, saltHex);
  return keyHex === result;
}
