import { RecipientWithPublicKey, EmailAndSubject, EmailAndSubjectEncrypted, HybridEncKey } from '../types';
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
 * Encrypts the email and its subject using hybrid encryption for multiple recipients.
 *
 * @param email - The email and subject to encrypt for multiple recipients.
 * @param recipients - The recipients with corresponding public keys.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The set of encrypted keys and encrypted email and subject
 */
export async function encryptEmailAndSubjectHybridForMultipleRecipients(
  email: EmailAndSubject,
  recipients: RecipientWithPublicKey[],
  aux?: Uint8Array,
): Promise<{  encryptedKeys: HybridEncKey[];
  encEmail: EmailAndSubjectEncrypted}> {
  try {
    if (!recipients || recipients.length === 0) {
      throw new InvalidInputEmail();
    }
    const { encryptionKey, encEmail } = await encryptEmailAndSubject(email, aux);

     const encryptedKeys = await Promise.all(
      recipients.map((recipient) => encryptKeysHybrid(encryptionKey, recipient)),
    );

    return {encEmail, encryptedKeys};
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
 * @param encEmail - The encrypted email and subject.
 * @param encryptedKey - The encrypted key for this recipient.
 * @param recipientPrivateHybridKeys - The private key of the recipient.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The decrypted email and subject
 */
export async function decryptEmailAndSubjectHybrid(
  encEmail: EmailAndSubjectEncrypted,
  encryptedKey: HybridEncKey,
  recipientPrivateHybridKeys: Uint8Array,
  aux?: Uint8Array,
): Promise<EmailAndSubject> {
  try {
    const encryptionKey = await decryptKeysHybrid(encryptedKey, recipientPrivateHybridKeys);
    return await decryptEmailAndSubject(encEmail, encryptionKey, aux);
  } catch (error) {
    if (error instanceof InvalidInputEmail) throw error;
    if (error instanceof EmailHybridDecryptionError) throw error;
    if (error instanceof EmailSymmetricDecryptionError) throw error;
    throw new FailedToDecryptEmail(error instanceof Error ? error.message : String(error));
  }
}
