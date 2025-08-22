import { getHash } from '../hash';

import { KEY_WRAPPING_ALGORITHM, KEY_FORMAT, AES_KEY_BIT_LENGTH, AES_ALGORITHM } from '../utils';

export async function importWrappingKey(key: Uint8Array): Promise<CryptoKey> {
  try {
    return await window.crypto.subtle.importKey(KEY_FORMAT, key, KEY_WRAPPING_ALGORITHM, false, [
      'wrapKey',
      'unwrapKey',
    ]);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to import wrapping key: ${errorMessage}`);
  }
}
export async function deriveWrappingKey(eccSecret: Uint8Array, kyberSecret: Uint8Array): Promise<CryptoKey> {
  try {
    if (eccSecret.length !== kyberSecret.length) {
      throw new Error('secrets must have equal length');
    }
    const key = await getHash(AES_KEY_BIT_LENGTH, [kyberSecret, eccSecret]);
    return await importWrappingKey(key);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to derive wrapping key: ${errorMessage}`);
  }
}

export async function unwrapKey(encryptedKey: Uint8Array, wrappingKey: CryptoKey): Promise<CryptoKey> {
  try {
    return await window.crypto.subtle.unwrapKey(
      KEY_FORMAT,
      encryptedKey,
      wrappingKey,
      KEY_WRAPPING_ALGORITHM,
      AES_ALGORITHM,
      false,
      ['encrypt', 'decrypt'],
    );
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to unwrap key: ${errorMessage}`);
  }
}

export async function wrapKey(encryptionKey: CryptoKey, wrappingKey: CryptoKey): Promise<Uint8Array> {
  try {
    const result = await window.crypto.subtle.wrapKey(KEY_FORMAT, encryptionKey, wrappingKey, KEY_WRAPPING_ALGORITHM);
    return new Uint8Array(result);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to wrap key: ${errorMessage}`);
  }
}
