import { AES_ALGORITHM, SymmetricCiphertext } from '../utils';
import { createIV, genAuxFromParams } from './core';

export async function encryptSymmetrically(
  encryptionKey: CryptoKey,
  nonce: number,
  message: Uint8Array,
  aux: string,
): Promise<SymmetricCiphertext> {
  try {
    const iv = createIV(nonce);
    const additionalData = await genAuxFromParams([aux, AES_ALGORITHM]);
    const encrypted = await window.crypto.subtle.encrypt(
      { name: AES_ALGORITHM, iv, additionalData },
      encryptionKey,
      message,
    );
    const ciphertext = new Uint8Array(encrypted);
    return { ciphertext, iv };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to encrypt symmetrically:${errorMessage}`));
  }
}

export async function decryptSymmetrically(
  encryptionKey: CryptoKey,
  encText: SymmetricCiphertext,
  aux: string,
): Promise<Uint8Array> {
  try {
    const additionalData = await genAuxFromParams([aux, AES_ALGORITHM]);
    const decrypted = await window.crypto.subtle.decrypt(
      { name: AES_ALGORITHM, iv: encText.iv, additionalData },
      encryptionKey,
      encText.ciphertext,
    );
    return new Uint8Array(decrypted);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to decrypt symmetrically:${errorMessage}`));
  }
}
