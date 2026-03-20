import { HybridEncryptedEmail, EmailBody, RecipientWithPublicKey } from '../types';
import { decryptEmailBody, encryptKeysHybrid, decryptKeysHybrid, encryptEmailBody } from './core';

/**
 * Encrypts the email body using hybrid encryption.
 *
 * @param body - The email body to encrypt.
 * @param recipientPublicKeys - The public keys of the recipient.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The encrypted email body
 */
export async function encryptEmailHybrid(
  body: EmailBody,
  recipient: RecipientWithPublicKey,
  aux?: Uint8Array,
): Promise<HybridEncryptedEmail> {
  try {
    const { encryptionKey, encEmailBody } = await encryptEmailBody(body, aux);
    const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient);
    return { encEmailBody, encryptedKey };
  } catch (error) {
    throw new Error('Failed to encrypt email body with hybrid encryption', { cause: error });
  }
}

/**
 * Encrypts the email body using hybrid encryption for multiple recipients.
 *
 * @param body - The email body to encrypt for multiple recipients.
 * @param recipients - The recipients with corresponding public keys.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The set of encrypted email bodies
 */
export async function encryptEmailHybridForMultipleRecipients(
  body: EmailBody,
  recipients: RecipientWithPublicKey[],
  aux?: Uint8Array,
): Promise<HybridEncryptedEmail[]> {
  try {
    const { encryptionKey, encEmailBody } = await encryptEmailBody(body, aux);

    const encryptedEmails: HybridEncryptedEmail[] = [];
    for (const recipient of recipients) {
      const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient);
      encryptedEmails.push({
        encEmailBody: encEmailBody,
        encryptedKey,
      });
    }
    return encryptedEmails;
  } catch (error) {
    throw new Error('Failed to encrypt email to multiple recipients with hybrid encryption', { cause: error });
  }
}

/**
 * Decrypts the email using hybrid encryption.
 *
 * @param encEmailBody - The encrypted email.
 * @param recipientPrivateHybridKeys - The private key of the recipient.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The decrypted email body
 */
export async function decryptEmailHybrid(
  encEmailBody: HybridEncryptedEmail,
  recipientPrivateHybridKeys: Uint8Array,
  aux?: Uint8Array,
): Promise<EmailBody> {
  try {
    const encryptionKey = await decryptKeysHybrid(encEmailBody.encryptedKey, recipientPrivateHybridKeys);
    const body = await decryptEmailBody(encEmailBody.encEmailBody, encryptionKey, aux);
    return body;
  } catch (error) {
    throw new Error('Failed to decrypt email with hybrid encryption', { cause: error });
  }
}
