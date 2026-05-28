import { HybridEncryptedEmail, Email, RecipientWithPublicKey } from '../types';
import { decryptEmail, encryptKeysHybrid, decryptKeysHybrid, encryptEmail } from './core';
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
 * Encrypts the email using hybrid encryption.
 *
 * @param email - The email to encrypt.
 * @param recipientPublicKeys - The public keys of the recipient.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The encrypted email
 */
export async function encryptEmailHybrid(
  email: Email,
  recipient: RecipientWithPublicKey,
  aux?: Uint8Array,
): Promise<HybridEncryptedEmail> {
  try {
    const { encryptionKey, encEmail } = await encryptEmail(email, aux);
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
 * Encrypts the email using hybrid encryption for multiple recipients.
 *
 * @param email - The email to encrypt for multiple recipients.
 * @param recipients - The recipients with corresponding public keys.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The set of encrypted emails
 */
export async function encryptEmailHybridForMultipleRecipients(
  email: Email,
  recipients: RecipientWithPublicKey[],
  aux?: Uint8Array,
): Promise<HybridEncryptedEmail[]> {
  try {
    if (!recipients || recipients.length === 0) {
      throw new InvalidInputEmail();
    }
    const { encryptionKey, encEmail } = await encryptEmail(email, aux);

    const encryptedEmails: HybridEncryptedEmail[] = [];
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
 * Decrypts the email using hybrid encryption.
 *
 * @param encEmail - The encrypted email.
 * @param recipientPrivateHybridKeys - The private key of the recipient.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The decrypted email
 */
export async function decryptEmailHybrid(
  encEmail: HybridEncryptedEmail,
  recipientPrivateHybridKeys: Uint8Array,
  aux?: Uint8Array,
): Promise<Email> {
  try {
    const encryptionKey = await decryptKeysHybrid(encEmail.encryptedKey, recipientPrivateHybridKeys);
    return await decryptEmail(encEmail.encEmail, encryptionKey, aux);
  } catch (error) {
    if (error instanceof EmailHybridDecryptionError) throw error;
    if (error instanceof EmailSymmetricDecryptionError) throw error;
    throw new FailedToDecryptEmail(error instanceof Error ? error.message : String(error));
  }
}
