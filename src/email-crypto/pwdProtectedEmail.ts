import { PwdProtectedEmail, EmailBody } from '../types';
import { decryptEmailBody, passwordProtectKey, removePasswordProtection, encryptEmailBody } from './core';

/**
 * Creates a password-protected email.
 *
 * @param email - The email to password-protect
 * @param password - The secret password shared among recipients
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The password-protected email
 */
export async function createPwdProtectedEmail(
  emailBody: EmailBody,
  password: string,
  aux?: Uint8Array,
): Promise<PwdProtectedEmail> {
  try {
    const { encryptionKey, encEmailBody } = await encryptEmailBody(emailBody, aux);
    const encryptedKey = await passwordProtectKey(encryptionKey, password);

    return { encEmailBody, encryptedKey };
  } catch (error) {
    throw new Error('Failed to password-protect email', { cause: error });
  }
}

/**
 * Opens a password-protected email.
 *
 * @param encryptedEmail - The encrypted email
 * @param password - The secret password shared among recipients.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The decrypted email body
 */
export async function decryptPwdProtectedEmail(
  encryptedEmail: PwdProtectedEmail,
  password: string,
  aux?: Uint8Array,
): Promise<EmailBody> {
  try {
    const encryptionKey = await removePasswordProtection(encryptedEmail.encryptedKey, password);
    const body = await decryptEmailBody(encryptedEmail.encEmailBody, encryptionKey, aux);
    return body;
  } catch (error) {
    throw new Error('Failed to decrypt password-protect email', { cause: error });
  }
}
