import { EmailBodyAndSubject, PwdProtectedEmailAndSubject } from '../types';
import { passwordProtectKey, removePasswordProtection } from './core';
import { encryptEmailBodyAndSubject, decryptEmailBodyAndSubject } from './coreSubject';
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
  emailBody: EmailBodyAndSubject,
  password: string,
  aux?: Uint8Array,
): Promise<PwdProtectedEmailAndSubject> {
  try {
    const { encryptionKey, encEmailBody } = await encryptEmailBodyAndSubject(emailBody, aux);
    const encryptedKey = await passwordProtectKey(encryptionKey, password);

    return { encEmailBody, encryptedKey };
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
 * @returns The decrypted email body
 */
export async function decryptPwdProtectedEmailAndSubject(
  encryptedEmail: PwdProtectedEmailAndSubject,
  password: string,
  aux?: Uint8Array,
): Promise<EmailBodyAndSubject> {
  try {
    const encryptionKey = await removePasswordProtection(encryptedEmail.encryptedKey, password);

    const body = await decryptEmailBodyAndSubject(encryptedEmail.encEmailBody, encryptionKey, aux);
    return body;
  } catch (error) {
    if (error instanceof InvalidInputEmail) throw error;
    if (error instanceof EmailPasswordOpenError) throw error;
    if (error instanceof EmailSymmetricDecryptionError) throw error;
    throw new FailedToDecryptEmail(error instanceof Error ? error.message : String(error));
  }
}
