import { PwdProtectedEmail, Email } from '../types';
import { decryptEmailBody, passwordProtectKey, removePasswordProtection, encryptEmailBody } from './core';

/**
 * Creates a password-protected email.
 *
 * @param email - The email to password-protect
 * @param password - The secret password shared among recipients
 * @param isSubjectEncrypted -  Indicates if the email subject field should be encrypted
 * @returns The password-protected email
 */
export async function createPwdProtectedEmail(
  email: Email,
  password: string,
  isSubjectEncrypted: boolean = false,
): Promise<PwdProtectedEmail> {
  try {
    if (!email?.body || !email.params) {
      throw new Error('Failed to password-protect email: Invalid email structure');
    }
    const { encryptionKey, params, enc } = await encryptEmailBody(email, isSubjectEncrypted);
    const encryptedKey = await passwordProtectKey(encryptionKey, password);

    return { enc, encryptedKey, params, id: email.id, isSubjectEncrypted };
  } catch (error) {
    throw new Error('Failed to password-protect email', { cause: error });
  }
}

/**
 * Opens a password-protected email.
 *
 * @param encryptedEmail - The encrypted email
 * @param password - The secret password shared among recipients.
 * @returns The decrypted email
 */
export async function decryptPwdProtectedEmail(encryptedEmail: PwdProtectedEmail, password: string): Promise<Email> {
  try {
    const { isSubjectEncrypted, params: encParams, enc, id } = encryptedEmail;
    const encryptionKey = await removePasswordProtection(encryptedEmail.encryptedKey, password);
    const { body, params } = await decryptEmailBody(enc, encParams, encryptionKey, isSubjectEncrypted);
    return { body, params, id };
  } catch (error) {
    throw new Error('Failed to decrypt password-protect email', { cause: error });
  }
}
