import { AES_ALGORITHM, AES_KEY_BIT_LENGTH, KEY_FORMAT } from '../utils';

export async function importSymmetricCryptoKey(keyData: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    KEY_FORMAT,
    keyData,
    {
      name: AES_ALGORITHM,
      length: AES_KEY_BIT_LENGTH,
    },
    true,
    ['encrypt', 'decrypt'],
  );
}

export async function exportSymmetricCryptoKey(key: CryptoKey): Promise<Uint8Array> {
  const rawKey = await crypto.subtle.exportKey(KEY_FORMAT, key);
  return new Uint8Array(rawKey);
}

export async function genSymmetricCryptoKey(): Promise<CryptoKey> {
  return window.crypto.subtle.generateKey(
    {
      name: AES_ALGORITHM,
      length: AES_KEY_BIT_LENGTH,
    },
    true,
    ['encrypt', 'decrypt'],
  );
}

export function genSymmetricKey(): Uint8Array {
  const key = new Uint8Array(AES_KEY_BIT_LENGTH / 8);
  window.crypto.getRandomValues(key);
  return key;
}
