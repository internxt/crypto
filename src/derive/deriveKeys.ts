import { blake3, createBLAKE3 } from 'hash-wasm';
import { AES_KEY_BIT_LENGTH, HASH_BIT_LEN } from '../utils/constants';
import { importSymmetricCryptoKey } from '../symmetric';
import { hexToUint8Array } from '../utils/converters';

export async function deriveSymmetricCryptoKeyFromContext(context: string, baseKey: Uint8Array): Promise<CryptoKey> {
  try {
    if (baseKey.length < AES_KEY_BIT_LENGTH / 8) {
      throw new Error('Base key is too short');
    }
    if (!context) {
      throw new Error('Context is not provided');
    }
    const context_key = await blake3(context);
    const buffer_context_key = hexToUint8Array(context_key);
    const result = await blake3(baseKey, AES_KEY_BIT_LENGTH, buffer_context_key);
    const keyBytes = hexToUint8Array(result);

    const key = await importSymmetricCryptoKey(keyBytes);
    return key;
  } catch (error) {
    return Promise.reject(new Error(`CryptoKey derivation from base key failed: ${error}`));
  }
}

export async function deriveSymmetricKeyFromTwoKeys(
  key1: Uint8Array,
  key2: Uint8Array,
  context: string | Uint8Array,
): Promise<Uint8Array> {
  try {
    if (key2.length != 32) {
      throw new Error('Key length must be exactly 32 bytes');
    }
    const hasher = await createBLAKE3(HASH_BIT_LEN, key1);
    hasher.init();
    hasher.update(context);
    hasher.update(key2);
    return hasher.digest('binary');
  } catch (error) {
    return Promise.reject(new Error(`Key derivation failed: ${error}`));
  }
}
