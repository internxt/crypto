import { PwdProtectedEmail, Email } from '../types';
import {
  encryptEmailContentSymmetrically,
  decryptEmailSymmetrically,
  passwordProtectKey,
  removePasswordProtection,
} from './core';
import { getAux } from './utils';

/**
 * Creates a password-protected email.
 *
 * @param email - The email to password-protect
 * @param password - The secret password shared among recipients.
 * @returns The password-protected email
 */
export async function createPwdProtectedEmail(email: Email, password: string): Promise<PwdProtectedEmail> {
  try {
    if (!email?.body || !email.params) {
      throw new Error('Failed to password-protect email: Invalid email structure');
    }
    const aux = getAux(email.params);
    const { enc, encryptionKey } = await encryptEmailContentSymmetrically(email.body, aux, email.id);
    const encryptedKey = await passwordProtectKey(encryptionKey, password);
    return { enc, encryptedKey, params: email.params, id: email.id };
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
    const aux = getAux(encryptedEmail.params);
    const encryptionKey = await removePasswordProtection(encryptedEmail.encryptedKey, password);
    const body = await decryptEmailSymmetrically(encryptionKey, aux, encryptedEmail.enc);
    return { body, params: encryptedEmail.params, id: encryptedEmail.id };
  } catch (error) {
    throw new Error('Failed to decrypt password-protect email', { cause: error });
  }
}
