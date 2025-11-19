import { createNISTbasedIV, makeAuxFixedLength, encryptMessage, decryptMessage } from './core';
import { concatBytes } from '@noble/hashes/utils.js';
import { IV_LEN_BYTES } from '../constants';

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
): Promise<Uint8Array> {
  try {
    const iv = createNISTbasedIV(freeField);
    const additionalData = await makeAuxFixedLength(aux);
    const ciphertext = await encryptMessage(message, encryptionKey, iv, additionalData);
    return concatBytes(ciphertext, iv);
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
  encryptedMessage: Uint8Array,
  aux: string,
): Promise<Uint8Array> {
  try {
    const additionalData = await makeAuxFixedLength(aux);
    const ciphertext = encryptedMessage.slice(0, encryptedMessage.length - IV_LEN_BYTES);
    const iv = encryptedMessage.slice(encryptedMessage.length - IV_LEN_BYTES);
    const result = await decryptMessage(ciphertext, iv, encryptionKey, additionalData);
    return result;
  } catch (error) {
    throw new Error('Failed to decrypt symmetrically', { cause: error });
  }
}
