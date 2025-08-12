import { AES_ALGORITHM } from '../utils/constants';
import { createIV, genAuxFromParams } from './utils';

export async function encryptSymmetrically(
  encryptionKey: CryptoKey,
  nonce: number,
  message: Uint8Array,
  aux: string,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
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
  iv: Uint8Array,
  cipherText: Uint8Array,
  aux: string,
): Promise<Uint8Array> {
  const additionalData = await genAuxFromParams([aux, AES_ALGORITHM]);
  const decrypted = await window.crypto.subtle.decrypt(
    { name: AES_ALGORITHM, iv, additionalData },
    encryptionKey,
    cipherText,
  );
  return new Uint8Array(decrypted);
}
