import {
  ARGON2ID_ITERATIONS,
  ARGON2ID_MEMORY_SIZE,
  ARGON2ID_PARALLELISM,
  ARGON2ID_SALT_BYTE_LENGTH,
  ARGON2ID_OUTPUT_BYTE_LENGTH,
} from '../utils/constants';

import { argon2, argon2Hex } from './utils';

export async function getKeyFromPassword(password: string): Promise<{ key: Uint8Array; salt: Uint8Array }> {
  try {
    const salt = new Uint8Array(ARGON2ID_SALT_BYTE_LENGTH);
    window.crypto.getRandomValues(salt);
    const key = await getKeyFromPasswordAndSalt(password, salt);
    return { key, salt };
  } catch (error) {
    return Promise.reject(new Error(`Key derivation from password failed: ${error}`));
  }
}

export async function getKeyFromPasswordHex(password: string): Promise<{ hash: string; salt: Uint8Array }> {
  try {
    const salt = new Uint8Array(ARGON2ID_SALT_BYTE_LENGTH);
    window.crypto.getRandomValues(salt);
    const result = await getKeyFromPasswordAndSaltHex(password, salt);
    return { hash: result, salt };
  } catch (error) {
    return Promise.reject(new Error(`Key derivation from password failed: ${error}`));
  }
}

export async function getKeyFromPasswordAndSaltHex(password: string, salt: string | Uint8Array): Promise<string> {
  return argon2Hex(
    password,
    salt,
    ARGON2ID_PARALLELISM,
    ARGON2ID_ITERATIONS,
    ARGON2ID_MEMORY_SIZE,
    ARGON2ID_OUTPUT_BYTE_LENGTH,
  );
}

export async function getKeyFromPasswordAndSalt(password: string, salt: string | Uint8Array): Promise<Uint8Array> {
  return argon2(
    password,
    salt,
    ARGON2ID_PARALLELISM,
    ARGON2ID_ITERATIONS,
    ARGON2ID_MEMORY_SIZE,
    ARGON2ID_OUTPUT_BYTE_LENGTH,
  );
}

export async function verifyKeyFromPasswordAndSaltHex(
  password: string,
  salt: string | Uint8Array,
  keyHex: string,
): Promise<boolean> {
  const hashHex = await getKeyFromPasswordAndSaltHex(password, salt);
  return keyHex === hashHex;
}
