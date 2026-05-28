import { EmailAndSubject, PwdProtectedEmailAndSubject } from '../types';
import { passwordProtectKey, removePasswordProtection } from './core';
import { encryptEmailAndSubject, decryptEmailAndSubject } from './coreSubject';
import {
  FailedToDecryptEmail,
  FailedToEncryptEmail,
  InvalidInputEmail,
  EmailPasswordOpenError,
  EmailPasswordProtectError,
  EmailSymmetricDecryptionError,
  EmailSymmetricEncryptionError,
} from './errors';

/**
 * Creates a password-protected email and subject.
 *
 * @param email - The email and subject to password-protect
 * @param password - The secret password shared among recipients
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The password-protected email
 */
export async function createPwdProtectedEmailAndSubject(
  email: EmailAndSubject,
  password: string,
  aux?: Uint8Array,
): Promise<PwdProtectedEmailAndSubject> {
  try {
    const { encryptionKey, encEmail } = await encryptEmailAndSubject(email, aux);
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
 * Opens a password-protected email and subject.
 *
 * @param encryptedEmail - The encrypted email and subject
 * @param password - The secret password shared among recipients.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The decrypted email and subject
 */
export async function decryptPwdProtectedEmailAndSubject(
  encryptedEmail: PwdProtectedEmailAndSubject,
  password: string,
  aux?: Uint8Array,
): Promise<EmailAndSubject> {
  if (!encryptedEmail || !encryptedEmail.encEmail || !encryptedEmail.encryptedKey) {
    throw new InvalidInputEmail();
  }
  try {
    const encryptionKey = await removePasswordProtection(encryptedEmail.encryptedKey, password);
    return await decryptEmailAndSubject(encryptedEmail.encEmail, encryptionKey, aux);
  } catch (error) {
    if (error instanceof EmailPasswordOpenError) throw error;
    if (error instanceof EmailSymmetricDecryptionError) throw error;
    throw new FailedToDecryptEmail(error instanceof Error ? error.message : String(error));
  }
}
