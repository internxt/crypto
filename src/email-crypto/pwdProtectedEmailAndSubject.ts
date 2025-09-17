import { ciphertextToBase64, base64ToCiphertext } from '../utils';
import { PwdProtectedEmail, Email } from '../types';
import {
  encryptEmailContentAndSubjectSymmetrically,
  decryptEmailAndSubjectSymmetrically,
  passwordProtectKey,
  removePasswordProtection,
} from './core';
import { getAuxWithoutSubject } from './utils';

/**
 * Creates a password-protected email and its subject.
 *
 * @param email - The email to password-protect
 * @param password - The secret password shared among recipients.
 * @returns The password-protected email with encrypted email subject
 */
export async function createPwdProtectedEmailAndSubject(email: Email, password: string): Promise<PwdProtectedEmail> {
  try {
    const aux = getAuxWithoutSubject(email.params);
    const { enc, encryptionKey, subjectEnc } = await encryptEmailContentAndSubjectSymmetrically(
      email.body,
      email.params.subject,
      aux,
      email.params.id,
    );
    const encryptedKey = await passwordProtectKey(encryptionKey, password);
    const encSubjectStr = ciphertextToBase64(subjectEnc);
    const params = { ...email.params, subject: encSubjectStr };
    return { enc, encryptedKey, params };
  } catch (error) {
    throw new Error('Failed to password-protect email and subject', { cause: error });
  }
}

/**
 * Opens a password-protected email.
 *
 * @param encryptedEmail - The encrypted email with encrypted email subject.
 * @param password - The secret password shared among recipients.
 * @returns The decrypted email and email subject
 */
export async function decryptPwdProtectedEmailAndSubject(
  encryptedEmail: PwdProtectedEmail,
  password: string,
): Promise<Email> {
  try {
    const aux = getAuxWithoutSubject(encryptedEmail.params);
    const encryptionKey = await removePasswordProtection(encryptedEmail.encryptedKey, password);
    const encSubject = base64ToCiphertext(encryptedEmail.params.subject);
    const { body, subject } = await decryptEmailAndSubjectSymmetrically(
      encryptedEmail.enc,
      encSubject,
      encryptionKey,
      aux,
    );
    const params = { ...encryptedEmail.params, subject };
    return { body, params };
  } catch (error) {
    throw new Error('Failed to decrypt password-protect email', { cause: error });
  }
}
