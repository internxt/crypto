import { EmailBodyAndSubject, EmailBodyAndSubjectEncrypted } from '../types';
import { encryptSymmetrically, decryptSymmetrically, genSymmetricKey } from '../symmetric-crypto';
import { encryptEmailBodyWithKey, decryptEmailBody } from './core';
import { UTF8ToUint8, base64ToUint8Array, uint8ArrayToBase64, uint8ToUTF8 } from '../utils';
import { InvalidInputEmail, EmailSymmetricDecryptionError, EmailSymmetricEncryptionError } from './errors';

/**
 * Symmetrically encrypts email body and subject.
 *
 * @param body - The email body and subject to encrypt.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The resulting encrypted email body and symmetric key used for encryption
 */
export async function encryptEmailBodyAndSubject(
  body: EmailBodyAndSubject,
  aux?: Uint8Array,
): Promise<{
  encEmailBody: EmailBodyAndSubjectEncrypted;
  encryptionKey: Uint8Array;
}> {
  try {
    if (!body.text || !body.subject) {
      throw new InvalidInputEmail();
    }
    const encryptionKey = genSymmetricKey();
    const encEmailBody = await encryptEmailBodyAndSubjectWithKey(body, encryptionKey, aux);

    return { encEmailBody, encryptionKey };
  } catch (error) {
    if (error instanceof InvalidInputEmail) throw error;
    throw new EmailSymmetricEncryptionError(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Symmetrically encrypts email body and subject with the given key.
 *
 * @param body - The email body and subject to encrypt.
 * @param encryptionKey - The symmetric key to encrypt the email.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The resulting encrypted email body and symmetric key used for encryption
 */
export async function encryptEmailBodyAndSubjectWithKey(
  body: EmailBodyAndSubject,
  encryptionKey: Uint8Array,
  aux?: Uint8Array,
): Promise<EmailBodyAndSubjectEncrypted> {
  try {
    const enc = await encryptEmailBodyWithKey(body, encryptionKey, aux);
    const subject = UTF8ToUint8(body.subject);
    const subjectEnc = await encryptSymmetrically(encryptionKey, subject, aux);
    const encSubject = uint8ArrayToBase64(subjectEnc);

    return { ...enc, encSubject };
  } catch (error) {
    if (error instanceof InvalidInputEmail) throw error;
    throw new EmailSymmetricEncryptionError(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Decrypts symmetrically encrypted email body and subject.
 *
 * @param encEmailBody - The email body and subject to decrypt.
 * @param encryptionKey - The symmetric key to decrypt the email.
 * @param aux - An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The resulting decrypted email body
 */
export async function decryptEmailBodyAndSubject(
  encEmailBody: EmailBodyAndSubjectEncrypted,
  encryptionKey: Uint8Array,
  aux?: Uint8Array,
): Promise<EmailBodyAndSubject> {
  try {
    const encSubject = base64ToUint8Array(encEmailBody.encSubject);
    const subjectArray = await decryptSymmetrically(encryptionKey, encSubject, aux);
    const subject = uint8ToUTF8(subjectArray);
    const body = await decryptEmailBody(encEmailBody, encryptionKey, aux);

    return { ...body, subject };
  } catch (error) {
    if (error instanceof InvalidInputEmail) throw error;
    throw new EmailSymmetricDecryptionError(error instanceof Error ? error.message : String(error));
  }
}
