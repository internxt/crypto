import { PwdProtectedEmail, EmailBody } from '../types';
import {
  encryptEmailContentSymmetrically,
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
export async function createPwdProtectedEmail(
  email: EmailBody,
  password: string,
  aux: string,
  emailID: string,
): Promise<PwdProtectedEmail> {
  try {
    const { enc, encryptionKey } = await encryptEmailContentSymmetrically(email, aux, emailID);
    const encryptedKey = await passwordProtectKey(encryptionKey, password);
    return { enc, encryptedKey };
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
export async function decryptPwdProtectedEmail(encryptedEmail: PwdProtectedEmail, password: string, aux: string) {
  try {
    const encryptionKey = await removePasswordProtection(encryptedEmail.encryptedKey, password);
    const result = await decryptEmailSymmetrically(encryptedEmail.enc, encryptionKey, aux);
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to decrypt password-protect email: ${errorMessage}`));
  }
}
