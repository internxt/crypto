import { PwdProtectedEmail, Email } from '../types';
import { decryptEmail, passwordProtectKey, removePasswordProtection, encryptEmail } from './core';
import {
  EmailSymmetricEncryptionError,
  FailedToDecryptEmail,
  FailedToEncryptEmail,
  EmailPasswordProtectError,
  EmailSymmetricDecryptionError,
  EmailPasswordOpenError,
  InvalidInputEmail,
} from './errors';
/**
 * Creates a password-protected email.
 *
 * @param email - The email to password-protect
 * @param password - The secret password shared among recipients
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The password-protected email
 */
export async function createPwdProtectedEmail(
  email: Email,
  password: string,
  aux?: Uint8Array,
): Promise<PwdProtectedEmail> {
  try {
    const { encryptionKey, encEmail } = await encryptEmail(email, aux);
    const encryptedKey = await passwordProtectKey(encryptionKey, password);

    return { encEmail, encryptedKey };
  } catch (error) {
    if (error instanceof InvalidInputEmail) throw error;
    if (error instanceof EmailSymmetricEncryptionError) throw error;
    if (error instanceof EmailPasswordProtectError) throw error;
    throw new FailedToEncryptEmail(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Opens a password-protected email.
 *
 * @param encryptedEmail - The encrypted email
 * @param password - The secret password shared among recipients.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The decrypted email
 */
export async function decryptPwdProtectedEmail(
  encryptedEmail: PwdProtectedEmail,
  password: string,
  aux?: Uint8Array,
): Promise<Email> {
  try {
    const encryptionKey = await removePasswordProtection(encryptedEmail.encryptedKey, password);
    return await decryptEmail(encryptedEmail.encEmail, encryptionKey, aux);
  } catch (error) {
    if (error instanceof InvalidInputEmail) throw error;
    if (error instanceof EmailPasswordOpenError) throw error;
    if (error instanceof EmailSymmetricDecryptionError) throw error;
    throw new FailedToDecryptEmail(error instanceof Error ? error.message : String(error));
  }
}
