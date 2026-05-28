import { RecipientWithPublicKey, EmailBodyAndSubject, HybridEncryptedEmailAndSubject } from '../types';
import { encryptKeysHybrid, decryptKeysHybrid } from './core';
import { encryptEmailAndSubject, decryptEmailAndSubject } from './coreSubject';
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
 * Encrypts the email and its subject using hybrid encryption.
 *
 * @param email - The email and subject to encrypt.
 * @param recipientPublicKeys - The public keys of the recipient.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The encrypted email and subject
 */
export async function encryptEmailAndSubjectHybrid(
  email: EmailBodyAndSubject,
  recipient: RecipientWithPublicKey,
  aux?: Uint8Array,
): Promise<HybridEncryptedEmailAndSubject> {
  try {
    const { encryptionKey, encEmail } = await encryptEmailAndSubject(email, aux);
    const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient);
    return { encEmail, encryptedKey };
  } catch (error) {
    if (error instanceof InvalidInputEmail) throw error;
    if (error instanceof EmailSymmetricEncryptionError) throw error;
    if (error instanceof EmailHybridEncryptionError) throw error;
    throw new FailedToEncryptEmail(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Encrypts the email and its subject using hybrid encryption for multiple recipients.
 *
 * @param email - The email and subject to encrypt for multiple recipients.
 * @param recipients - The recipients with corresponding public keys.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The set of encrypted emails and subjects
 */
export async function encryptEmailAndSubjectHybridForMultipleRecipients(
  email: EmailBodyAndSubject,
  recipients: RecipientWithPublicKey[],
  aux?: Uint8Array,
): Promise<HybridEncryptedEmailAndSubject[]> {
  try {
    if (!recipients || recipients.length === 0) {
      throw new InvalidInputEmail();
    }
    const { encryptionKey, encEmail } = await encryptEmailAndSubject(email, aux);

    const encryptedEmails: HybridEncryptedEmailAndSubject[] = [];
    for (const recipient of recipients) {
      const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient);
      encryptedEmails.push({
        encEmail,
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
 * @returns The decrypted email and subject
 */
export async function decryptEmailAndSubjectHybrid(
  hybridEmail: HybridEncryptedEmailAndSubject,
  recipientPrivateHybridKeys: Uint8Array,
  aux?: Uint8Array,
): Promise<EmailBodyAndSubject> {
  try {
    const encryptionKey = await decryptKeysHybrid(hybridEmail.encryptedKey, recipientPrivateHybridKeys);
    return await decryptEmailAndSubject(hybridEmail.encEmail, encryptionKey, aux);
  } catch (error) {
    if (error instanceof InvalidInputEmail) throw error;
    if (error instanceof EmailHybridDecryptionError) throw error;
    if (error instanceof EmailSymmetricDecryptionError) throw error;
    throw new FailedToDecryptEmail(error instanceof Error ? error.message : String(error));
  }
}
