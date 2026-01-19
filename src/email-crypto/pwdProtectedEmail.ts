import { PwdProtectedEmail, Email, EmailBodyEncrypted, EmailBody } from '../types';
import {
  encryptEmailContentSymmetrically,
  decryptEmailSymmetrically,
  encryptEmailContentAndSubjectSymmetrically,
  decryptEmailAndSubjectSymmetrically,
  passwordProtectKey,
  removePasswordProtection,
} from './core';
import { getAux } from './utils';

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
    const aux = getAux(email.params, isSubjectEncrypted);

    let enc: EmailBodyEncrypted;
    let encryptionKey: CryptoKey;
    let params = email.params;

    if (isSubjectEncrypted) {
      const result = await encryptEmailContentAndSubjectSymmetrically(email.body, email.params.subject, aux, email.id);
      enc = result.enc;
      encryptionKey = result.encryptionKey;
      params = { ...email.params, subject: result.encSubject };
    } else {
      const result = await encryptEmailContentSymmetrically(email.body, aux, email.id);
      enc = result.enc;
      encryptionKey = result.encryptionKey;
    }
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
    const isSubjectEncrypted = encryptedEmail.isSubjectEncrypted;
    const aux = getAux(encryptedEmail.params, isSubjectEncrypted);
    const encryptionKey = await removePasswordProtection(encryptedEmail.encryptedKey, password);
    let body: EmailBody;
    let params = encryptedEmail.params;
    if (isSubjectEncrypted) {
      const result = await decryptEmailAndSubjectSymmetrically(
        encryptionKey,
        aux,
        encryptedEmail.params.subject,
        encryptedEmail.enc,
      );
      body = result.body;
      params = { ...encryptedEmail.params, subject: result.subject };
    } else {
      body = await decryptEmailSymmetrically(encryptionKey, aux, encryptedEmail.enc);
    }
    return { body, params, id: encryptedEmail.id };
  } catch (error) {
    throw new Error('Failed to decrypt password-protect email', { cause: error });
  }
}
