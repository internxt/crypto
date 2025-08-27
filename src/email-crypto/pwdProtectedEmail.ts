import { PwdProtectedEmail, Email } from '../types';
import {
  encryptEmailSymmetrically,
  decryptEmailSymmetrically,
  passwordProtectKey,
  removePasswordProtection,
} from './core';

/**
 * Creates a password-protected email.
 *
 * @param email - The email to protect
 * @param password - The secret password shared among recipients.
 * @returns The password-protected email
 */
export async function createPwdProtectedEmail(email: Email, password: string): Promise<PwdProtectedEmail> {
  try {
    const { encEmail: ciphertext, encryptionKey } = await encryptEmailSymmetrically(email);
    const encryptedKey = await passwordProtectKey(encryptionKey, password);
    const result: PwdProtectedEmail = {
      sender: email.sender,
      recipients: email.recipients,
      subject: email.subject,
      replyToEmailID: email.replyToEmailID,
      ciphertext,
      encryptedKey,
    };
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to password-protect email: ${errorMessage}`));
  }
}

/**
 * Opens a password-protected email.
 *
 * @param email - The email to protect
 * @param password - The secret password shared among recipients.
 * @returns The password-protected email
 */
export async function decryptPwdProtectedEmail(encryptedEmail: PwdProtectedEmail, password: string) {
  try {
    const encryptionKey = await removePasswordProtection(encryptedEmail.encryptedKey, password);
    const result = await decryptEmailSymmetrically(encryptedEmail, encryptionKey);
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to decrypt password-protect email: ${errorMessage}`));
  }
}
