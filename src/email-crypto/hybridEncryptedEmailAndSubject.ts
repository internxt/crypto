import { RecipientWithPublicKey, EmailBodyAndSubject, HybridEncryptedEmailAndSubject } from '../types';
import { encryptKeysHybrid, decryptKeysHybrid } from './core';
import { encryptEmailBodyAndSubject, decryptEmailBodyAndSubject } from './coreSubject';
import {
  FailedToDecryptEmail,
  FailedToEncryptEmail,
  EmailHybridDecryptionError,
  EmailHybridEncryptionError,
  InvalidInputEmail,
  EmailSymmetricDecryptionError,
  EmailSymmetricEncryptionError,
} from './errors';

/**
 * Encrypts the email body and its subject using hybrid encryption.
 *
 * @param body - The email body and subject to encrypt.
 * @param recipientPublicKeys - The public keys of the recipient.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The encrypted email body
 */
export async function encryptEmailAndSubjectHybrid(
  body: EmailBodyAndSubject,
  recipient: RecipientWithPublicKey,
  aux?: Uint8Array,
): Promise<HybridEncryptedEmailAndSubject> {
  try {
    const { encryptionKey, encEmailBody } = await encryptEmailBodyAndSubject(body, aux);
    const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient);
    return { encEmailBody, encryptedKey };
  } catch (error) {
    if (error instanceof InvalidInputEmail) throw error;
    if (error instanceof EmailSymmetricEncryptionError) throw error;
    if (error instanceof EmailHybridEncryptionError) throw error;
    throw new FailedToEncryptEmail(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Encrypts the email body and its subject using hybrid encryption for multiple recipients.
 *
 * @param body - The email body and subject to encrypt for multiple recipients.
 * @param recipients - The recipients with corresponding public keys.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The set of encrypted email bodies
 */
export async function encryptEmailAndSubjectHybridForMultipleRecipients(
  body: EmailBodyAndSubject,
  recipients: RecipientWithPublicKey[],
  aux?: Uint8Array,
): Promise<HybridEncryptedEmailAndSubject[]> {
  try {
    const { encryptionKey, encEmailBody } = await encryptEmailBodyAndSubject(body, aux);

    const encryptedEmails: HybridEncryptedEmailAndSubject[] = [];
    for (const recipient of recipients) {
      const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient);
      encryptedEmails.push({
        encEmailBody: encEmailBody,
        encryptedKey,
      });
    }
    return encryptedEmails;
  } catch (error) {
    if (error instanceof InvalidInputEmail) throw error;
    if (error instanceof EmailSymmetricEncryptionError) throw error;
    if (error instanceof EmailHybridEncryptionError) throw error;
    throw new FailedToEncryptEmail(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Decrypts the email and its subject using hybrid encryption.
 *
 * @param hybridEmail - The encrypted email and subject.
 * @param recipientPrivateHybridKeys - The private key of the recipient.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The decrypted email body
 */
export async function decryptEmailAndSubjectHybrid(
  hybridEmail: HybridEncryptedEmailAndSubject,
  recipientPrivateHybridKeys: Uint8Array,
  aux?: Uint8Array,
): Promise<EmailBodyAndSubject> {
  try {
    const encryptionKey = await decryptKeysHybrid(hybridEmail.encryptedKey, recipientPrivateHybridKeys);
    return await decryptEmailBodyAndSubject(hybridEmail.encEmailBody, encryptionKey, aux);
  } catch (error) {
    if (error instanceof InvalidInputEmail) throw error;
    if (error instanceof EmailHybridDecryptionError) throw error;
    if (error instanceof EmailSymmetricDecryptionError) throw error;
    throw new FailedToDecryptEmail(error instanceof Error ? error.message : String(error));
  }
}
