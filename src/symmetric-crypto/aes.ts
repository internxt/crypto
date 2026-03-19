import { concatBytes, randomBytes } from '@noble/hashes/utils.js';
import { IV_LEN_BYTES, AES_KEY_BYTE_LENGTH } from '../constants';
import { gcm as aeadCipher } from '@noble/ciphers/webcrypto.js';

/**
 * Symmetrically encrypts the message
 *
 * @param encryptionKey - The symmetric key used for message encryption
 * @param message - The message to encrypt
 * @param aux - The auxilary string (e.g., context string or timestamp) for AEAD.
 * @returns The resulting ciphertext.
 */
export async function encryptSymmetrically(
  encryptionKey: Uint8Array,
  message: Uint8Array,
  aux?: Uint8Array,
): Promise<Uint8Array> {
  try {
    const iv = randomBytes(IV_LEN_BYTES);
    const ciphertext = await aeadCipher(encryptionKey, iv, aux).encrypt(message);
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
 * @param aux - The auxilary string (e.g., context string or timestamp) for AEAD.
 * @returns The resulting ciphertext.
 */
export async function decryptSymmetrically(
  encryptionKey: Uint8Array,
  encryptedMessage: Uint8Array,
  aux?: Uint8Array,
): Promise<Uint8Array> {
  try {
    const ciphertext = encryptedMessage.slice(0, encryptedMessage.length - IV_LEN_BYTES);
    const iv = encryptedMessage.slice(encryptedMessage.length - IV_LEN_BYTES);
    const result = await aeadCipher(encryptionKey, iv, aux).decrypt(ciphertext);
    return result;
  } catch (error) {
    throw new Error('Failed to decrypt symmetrically', { cause: error });
  }
}

/**
 * Generates symmetric key as Uint8Array
 *
 * @returns The generated Uint8Array.
 */
export function genSymmetricKey(): Uint8Array {
  return randomBytes(AES_KEY_BYTE_LENGTH);
}
