import { CURVE_NAME, ECC_ALGORITHM } from '../utils/constants';

export async function generateEccKeys(): Promise<CryptoKeyPair> {
  try {
    return window.crypto.subtle.generateKey(
      {
        name: ECC_ALGORITHM,
        namedCurve: CURVE_NAME,
      },
      false,
      ['deriveBits'],
    );
  } catch (error) {
    return Promise.reject(new Error(`Failed to generate ECC keys: ${error.message}`));
  }
}

export async function exportPublicKey(key: CryptoKey): Promise<ArrayBuffer> {
  try {
    return await window.crypto.subtle.exportKey('spki', key);
  } catch (error) {
    return Promise.reject(new Error(`Failed to export public key: ${error}`));
  }
}

export async function importPublicKey(spkiKeyData: ArrayBuffer): Promise<CryptoKey> {
  try {
    return await window.crypto.subtle.importKey(
      'spki',
      spkiKeyData,
      {
        name: ECC_ALGORITHM,
        namedCurve: CURVE_NAME,
      },
      true,
      ['deriveBits'],
    );
  } catch (error) {
    return Promise.reject(new Error(`Failed to import public key: ${error}`));
  }
}
