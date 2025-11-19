import { SymmetricCiphertext } from '../types';
import { createNISTbasedIV, makeAuxFixedLength, encryptMessage, decryptMessage } from './core';

/**
 * Symmetrically encrypts the message
 *
 * @param encryptionKey - The symmetric CryptoKey used for message encryption
 * @param message - The message to encrypt
 * @param freeField - The context of the message (required for IV generation)
 * @param aux - The auxilary string
 * @returns The resulting ciphertext.
 */
export async function encryptSymmetrically(
  encryptionKey: CryptoKey,
  message: Uint8Array,
  aux: string,
  freeField?: string,
): Promise<SymmetricCiphertext> {
  try {
    const iv = createNISTbasedIV(freeField);
    const additionalData = await makeAuxFixedLength(aux);
    const ciphertext = await encryptMessage(message, encryptionKey, iv, additionalData);
    return { ciphertext, iv };
  } catch (error) {
    throw new Error('Failed to encrypt symmetrically', { cause: error });
  }
}

/**
 * Decryps symmetrically encrypted message
 *
 * @param encryptionKey - The symmetric CryptoKey used for message encryption
 * @param encryptedMessage - The ciphertext
 * @param aux - The auxilary string
 * @returns The resulting ciphertext.
 */
export async function decryptSymmetrically(
  encryptionKey: CryptoKey,
  encryptedMessage: SymmetricCiphertext,
  aux: string,
): Promise<Uint8Array> {
  try {
    const additionalData = await makeAuxFixedLength(aux);
    const result = await decryptMessage(
      encryptedMessage.ciphertext,
      encryptedMessage.iv,
      encryptionKey,
      additionalData,
    );
    return result;
  } catch (error) {
    throw new Error('Failed to decrypt symmetrically', { cause: error });
  }
}
