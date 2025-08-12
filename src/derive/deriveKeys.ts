import { blake3, createBLAKE3 } from 'hash-wasm';
import { AES_KEY_BIT_LENGTH, HASH_BIT_LEN } from '../utils/constants';
import { Buffer } from 'buffer';
import { importSymmetricCryptoKey } from '../symmetric';

export async function deriveSymmetricKeyFromBaseKey(context: string, baseKey: Uint8Array): Promise<Uint8Array> {
  try {
    const key = await deriveBitsFromBaseKey(context, baseKey, AES_KEY_BIT_LENGTH);
    return key;
  } catch (error) {
    return Promise.reject(new Error(`Key derivation from base key failed: ${error}`));
  }
}

export async function deriveSymmetricCryptoKeyFromBaseKey(context: string, baseKey: Uint8Array): Promise<CryptoKey> {
  try {
    const keyBytes = await deriveSymmetricKeyFromBaseKey(context, baseKey);
    const key = await importSymmetricCryptoKey(keyBytes);
    return key;
  } catch (error) {
    return Promise.reject(new Error(`CryptoKey derivation from base key failed: ${error}`));
  }
}

export async function deriveBitsFromBaseKey(
  context: string,
  baseKey: string | Uint8Array,
  bits: number,
): Promise<Uint8Array> {
  try {
    const context_key = await blake3(context);

    const result = await blake3(baseKey, bits, Buffer.from(context_key, 'hex'));
    return new Uint8Array(Buffer.from(result, 'hex'));
  } catch (error) {
    return Promise.reject(new Error(`Bit derivation from base key failed: ${error}`));
  }
}

export async function deriveSymmetricKeyFromTwoKeys(
  key1: Uint8Array,
  key2: Uint8Array,
  context: string | Uint8Array,
): Promise<Uint8Array> {
  try {
    const hasher = await createBLAKE3(HASH_BIT_LEN, key1);
    hasher.init();
    hasher.update(context);
    hasher.update(key2);
    return hasher.digest('binary');
  } catch (error) {
    return Promise.reject(new Error(`Key derivation failed: ${error}`));
  }
}
