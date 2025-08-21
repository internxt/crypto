import { AES_ALGORITHM } from '../utils/constants';
import { createIV, genAuxFromParams } from './utils';
import { SymmetricCiphertext } from '../utils/types';

export async function encryptSymmetrically(
  encryptionKey: CryptoKey,
  nonce: number,
  message: Uint8Array,
  aux: string,
): Promise<SymmetricCiphertext> {
  const iv = createIV(nonce);
  const additionalData = await genAuxFromParams([aux, AES_ALGORITHM]);
  const encrypted = await window.crypto.subtle.encrypt(
    { name: AES_ALGORITHM, iv, additionalData },
    encryptionKey,
    message,
  );
  const ciphertext = new Uint8Array(encrypted);
  return { ciphertext, iv };
}

export async function decryptSymmetrically(
  encryptionKey: CryptoKey,
  encText: SymmetricCiphertext,
  aux: string,
): Promise<Uint8Array> {
  const additionalData = await genAuxFromParams([aux, AES_ALGORITHM]);
  const decrypted = await window.crypto.subtle.decrypt(
    { name: AES_ALGORITHM, iv: encText.iv, additionalData },
    encryptionKey,
    encText.ciphertext,
  );
  return new Uint8Array(decrypted);
}
