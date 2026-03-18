import { createNISTbasedIV, encryptMessage, decryptMessage } from './core';
import { concatBytes } from '@noble/hashes/utils.js';
import { IV_LEN_BYTES } from '../constants';

/**
 * Symmetrically encrypts the message
 *
 * @param encryptionKey - The symmetric key used for message encryption
 * @param message - The message to encrypt
 * @param freeField - The context of the message (required for IV generation)
 * @param aux - The auxilary string
 * @returns The resulting ciphertext.
 */
export async function encryptSymmetrically(
  encryptionKey: Uint8Array,
  message: Uint8Array,
  aux: Uint8Array,
  freeField?: Uint8Array,
): Promise<Uint8Array> {
  try {
    const iv = createNISTbasedIV(freeField);
    const ciphertext = await encryptMessage(message, encryptionKey, iv, aux);
    return concatBytes(ciphertext, iv);
  } catch (error) {
    throw new Error('Failed to encrypt symmetrically', { cause: error });
  }
}

/**
 * Decryps symmetrically encrypted message
 *
 * @param encryptionKey - The symmetric key used for message encryption
 * @param encryptedMessage - The ciphertext
 * @param aux - The auxilary string
 * @returns The resulting ciphertext.
 */
export async function decryptSymmetrically(
  encryptionKey: Uint8Array,
  encryptedMessage: Uint8Array,
  aux: Uint8Array,
): Promise<Uint8Array> {
  try {
    const ciphertext = encryptedMessage.slice(0, encryptedMessage.length - IV_LEN_BYTES);
    const iv = encryptedMessage.slice(encryptedMessage.length - IV_LEN_BYTES);
    const result = await decryptMessage(ciphertext, iv, encryptionKey, aux);
    return result;
  } catch (error) {
    throw new Error('Failed to decrypt symmetrically', { cause: error });
  }
}
