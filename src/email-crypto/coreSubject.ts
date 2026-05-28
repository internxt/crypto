import { EmailAndSubject, EmailAndSubjectEncrypted } from '../types';
import { encryptSymmetrically, decryptSymmetrically, genSymmetricKey } from '../symmetric-crypto';
import { encryptEmailWithKey, decryptEmail } from './core';
import { UTF8ToUint8, base64ToUint8Array, uint8ArrayToBase64, uint8ToUTF8 } from '../utils';
import { InvalidInputEmail, EmailSymmetricDecryptionError, EmailSymmetricEncryptionError } from './errors';

/**
 * Symmetrically encrypts email and subject.
 *
 * @param email - The email and subject to encrypt.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The resulting encrypted email and symmetric key used for encryption
 */
export async function encryptEmailAndSubject(
  email: EmailAndSubject,
  aux?: Uint8Array,
): Promise<{
  encEmail: EmailAndSubjectEncrypted;
  encryptionKey: Uint8Array;
}> {
  if (!email.text || !email.subject) {
    throw new InvalidInputEmail();
  }
  try {
    const encryptionKey = genSymmetricKey();
    const encEmail = await encryptEmailAndSubjectWithKey(email, encryptionKey, aux);

    return { encEmail, encryptionKey };
  } catch (error) {
    throw new EmailSymmetricEncryptionError(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Symmetrically encrypts email and subject with the given key.
 *
 * @param email - The email and subject to encrypt.
 * @param encryptionKey - The symmetric key to encrypt the email.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The resulting encrypted email and symmetric key used for encryption
 */
export async function encryptEmailAndSubjectWithKey(
  email: EmailAndSubject,
  encryptionKey: Uint8Array,
  aux?: Uint8Array,
): Promise<EmailAndSubjectEncrypted> {
  try {
    const enc = await encryptEmailWithKey(email, encryptionKey, aux);
    const subject = UTF8ToUint8(email.subject);
    const subjectEnc = await encryptSymmetrically(encryptionKey, subject, aux);
    const encSubject = uint8ArrayToBase64(subjectEnc);

    return { ...enc, encSubject };
  } catch (error) {
    throw new EmailSymmetricEncryptionError(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Decrypts symmetrically encrypted email and email subject.
 *
 * @param encEmail - The encrypted email and subject to decrypt.
 * @param encryptionKey - The symmetric key to decrypt the email.
 * @param aux - An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The resulting decrypted email and subject
 */
export async function decryptEmailAndSubject(
  encEmail: EmailAndSubjectEncrypted,
  encryptionKey: Uint8Array,
  aux?: Uint8Array,
): Promise<EmailAndSubject> {
  try {
    const encSubject = base64ToUint8Array(encEmail.encSubject);
    const subjectArray = await decryptSymmetrically(encryptionKey, encSubject, aux);
    const subject = uint8ToUTF8(subjectArray);
    const email = await decryptEmail(encEmail, encryptionKey, aux);

    return { ...email, subject };
  } catch (error) {
    throw new EmailSymmetricDecryptionError(error instanceof Error ? error.message : String(error));
  }
}
