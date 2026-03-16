import { gcm } from '@noble/ciphers/webcrypto.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { getBytesFromData } from '../hash';
import { AUX_BYTE_LEN, IV_LEN_BYTES } from '../constants';

/**
 * Creates an initialization vector (IV) using RGB-based construction (8.2.2 NIST Special Publication 800-38D)
 * Constructs a 128-bits IV from 2 fileds: the random field (at least 96 bits) and the free field (32 bits).
 * If free filed is empty, then the entier 128-bit IV is sampled randomly.
 *
 * @param freeFiled - The string with an unrestricted content. Can be a device identifier, etc.
 * @returns The resulting 128-bits initialization vector.
 */
export function createNISTbasedIV(freeField?: Uint8Array): Uint8Array {
  try {
    if (!freeField) {
      return randomBytes(IV_LEN_BYTES);
    }

    const iv = new Uint8Array(16);

    const randFiled = randomBytes(12);
    iv.set(randFiled, 0);

    const freeFiledFixedLength = getBytesFromData(4, freeField);
    iv.set(freeFiledFixedLength, 12);

    return iv;
  } catch (error) {
    throw new Error('Failed to create IV', { cause: error });
  }
}

/**
 * Hashes aux string to make it fixed-length
 *
 * @param aux - The auxilay string of arbitrary length
 * @returns The resulting fixed-length auxilary string.
 */
export async function makeAuxFixedLength(aux: Uint8Array): Promise<Uint8Array> {
  return getBytesFromData(AUX_BYTE_LEN, aux);
}

/**
 * Symmetrically encrypts message
 *
 * @param message - The message to encrypt
 * @param encryptionKey - The encryption key
 * @param iv - The initialization vector
 * @param additionalData - The auxilary data
 * @returns The resulting ciphertext
 */
export async function encryptMessage(
  message: Uint8Array,
  encryptionKey: Uint8Array,
  iv: Uint8Array,
  additionalData: Uint8Array,
): Promise<Uint8Array> {
  return gcm(encryptionKey, iv, additionalData).encrypt(message);
}

/**
 * Symmetrically decrypts message
 *
 * @param ciphertext - The encrypted message
 * @param ciphertext - The initialization vector
 * @param encryptionKey - The encryption key
 * @param additionalData - The auxilary data
 * @returns The resulting decrypted message
 */
export async function decryptMessage(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  encryptionKey: Uint8Array,
  additionalData: Uint8Array,
): Promise<Uint8Array> {
  return gcm(encryptionKey, iv, additionalData).decrypt(ciphertext);
}
