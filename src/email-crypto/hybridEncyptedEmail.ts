import { HybridEncryptedEmail, Email, UserWithPublicKey } from '../types';
import { decryptEmailBody, encryptKeysHybrid, decryptKeysHybrid, encryptEmailBody } from './core';

/**
 * Encrypts the email using hybrid encryption.
 *
 * @param email - The email to encrypt.
 * @param recipientPublicKeys - The public keys of the recipient.
 * @param isSubjectEncrypted -  Indicates if the email subject field should be encrypted
 * @returns The encrypted email
 */
export async function encryptEmailHybrid(
  email: Email,
  recipient: UserWithPublicKey,
  isSubjectEncrypted: boolean = false,
): Promise<HybridEncryptedEmail> {
  try {
    const { encryptionKey, params, enc } = await encryptEmailBody(email, isSubjectEncrypted);
    const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient.publicHybridKey);
    return { enc, encryptedKey, recipientEmail: recipient.email, params, isSubjectEncrypted, id: email.id };
  } catch (error) {
    throw new Error('Failed to encrypt email with hybrid encryption', { cause: error });
  }
}

/**
 * Encrypts the email using hybrid encryption for multiple recipients.
 *
 * @param email - The email to encrypt.
 * @param recipients - The recipients with corresponding public keys.
 * @param isSubjectEncrypted -  Indicates if the email subject field should be encrypted
 * @returns The set of encrypted email
 */
export async function encryptEmailHybridForMultipleRecipients(
  email: Email,
  recipients: UserWithPublicKey[],
  isSubjectEncrypted: boolean = false,
): Promise<HybridEncryptedEmail[]> {
  try {
    const { encryptionKey, params, enc } = await encryptEmailBody(email, isSubjectEncrypted);

    const encryptedEmails: HybridEncryptedEmail[] = [];
    for (const recipient of recipients) {
      const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient.publicHybridKey);
      encryptedEmails.push({
        enc,
        encryptedKey,
        recipientEmail: recipient.email,
        params,
        isSubjectEncrypted,
        id: email.id,
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
 * @param encryptedEmail - The encrypted email.
 * @param recipientPrivateHybridKeys - The private key of the recipient.
 * @returns The decrypted email
 */
export async function decryptEmailHybrid(
  encryptedEmail: HybridEncryptedEmail,
  recipientPrivateHybridKeys: Uint8Array,
): Promise<Email> {
  try {
    const { isSubjectEncrypted, params: encParams, enc, encryptedKey, id } = encryptedEmail;
    const encryptionKey = await decryptKeysHybrid(encryptedKey, recipientPrivateHybridKeys);
    const { body, params } = await decryptEmailBody(enc, encParams, encryptionKey, isSubjectEncrypted);
    return { body, params, id };
  } catch (error) {
    throw new Error('Failed to decrypt email with hybrid encryption', { cause: error });
  }
}
