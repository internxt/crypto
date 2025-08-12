import { argon2id } from 'hash-wasm';

import {
  ARGON2ID_ITERATIONS,
  ARGON2ID_MEMORY_SIZE,
  ARGON2ID_PARALLELISM,
  ARGON2ID_SALT_BYTE_LENGTH,
  ARGON2ID_OUTPUT_BYTE_LENGTH,
} from '../utils/constants';

export async function getKeyFromPassword(
  password: string,
): Promise<{ key: Uint8Array; salt: Uint8Array }> {
  const salt = new Uint8Array(ARGON2ID_SALT_BYTE_LENGTH);
  window.crypto.getRandomValues(salt);
  const key = await getKeyFromPasswordAndSalt(password, salt);
  return { key, salt };
}

export async function getKeyFromPasswordHex(password: string): Promise<string> {
  const salt = new Uint8Array(ARGON2ID_SALT_BYTE_LENGTH);
  window.crypto.getRandomValues(salt);
  return getKeyFromPasswordAndSaltHex(password, salt);
}

export async function argon2Hex(
  password: string,
  salt: string | Uint8Array,
  parallelism: number,
  iterations: number,
  memorySize: number,
  hashLength: number,
): Promise<string> {
  return argon2id({
    password,
    salt,
    parallelism,
    iterations,
    memorySize,
    hashLength,
    outputType: 'hex',
  });
}

export async function argon2(
  password: string,
  salt: string | Uint8Array,
  parallelism: number,
  iterations: number,
  memorySize: number,
  hashLength: number,
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

export async function getKeyFromPasswordAndSaltHex(
  password: string,
  salt: string | Uint8Array,
): Promise<string> {
  return argon2Hex(
    password,
    salt,
    ARGON2ID_PARALLELISM,
    ARGON2ID_ITERATIONS,
    ARGON2ID_MEMORY_SIZE,
    ARGON2ID_OUTPUT_BYTE_LENGTH,
  );
}

export async function getKeyFromPasswordAndSalt(
  password: string,
  salt: string | Uint8Array,
): Promise<Uint8Array> {
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
