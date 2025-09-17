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
    const aux = getAux(email.params);
    const { enc, encryptionKey } = await encryptEmailContentSymmetrically(email.body, aux, email.params.id);
    const encryptedKey = await passwordProtectKey(encryptionKey, password);
    return { enc, encryptedKey, params: email.params };
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
    const body = await decryptEmailSymmetrically(encryptedEmail.enc, encryptionKey, aux);
    return { body, params: encryptedEmail.params };
  } catch (error) {
    throw new Error('Failed to decrypt password-protect email', { cause: error });
  }
}
