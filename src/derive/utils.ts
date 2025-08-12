import { argon2id } from 'hash-wasm';

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
