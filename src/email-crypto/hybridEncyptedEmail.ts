import { Email, PublicKeys, PrivateKeys, HybridEncryptedEmail } from '../types';
import { encryptEmailSymmetrically, decryptEmailSymmetrically, encryptKeysHybrid, decryptKeysHybrid } from './core';

/**
 * Encrypts the email using hybrid encryption.
 *
 * @param email - The email to encrypt.
 * @param recipientPublicKeys - The public keys of the recipient.
 * @param senderPrivateKey - The private key of the sender.
 * @returns The encrypted email
 */
export async function encryptEmailHybrid(
  email: Email,
  recipientPublicKeys: PublicKeys,
  senderPrivateKey: PrivateKeys,
): Promise<HybridEncryptedEmail> {
  try {
    const { encEmail: ciphertext, encryptionKey } = await encryptEmailSymmetrically(email);
    const encryptedKey = await encryptKeysHybrid(encryptionKey, recipientPublicKeys, senderPrivateKey);
    const result: HybridEncryptedEmail = {
      recipients: email.recipients,
      encryptedFor: recipientPublicKeys.userID,
      sender: email.sender,
      subject: email.subject,
      replyToEmailID: email.replyToEmailID,
      ciphertext,
      encryptedKey,
    };

    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to encrypt email with hybrid encryption: ${errorMessage}`));
  }
}

/**
 * Encrypts the email using hybrid encryption for multiple recipients.
 *
 * @param email - The email to encrypt.
 * @param recipientsPublicKeys - The public keys of all the recipients.
 * @param senderPrivateKey - The private key of the sender.
 * @returns The set of encrypted email
 */
export async function encryptEmailHybridForMultipleRecipients(
  email: Email,
  recipientsPublicKeys: PublicKeys[],
  senderPrivateKey: PrivateKeys,
): Promise<HybridEncryptedEmail[]> {
  try {
    const { encEmail: ciphertext, encryptionKey } = await encryptEmailSymmetrically(email);

    const encryptedEmails: HybridEncryptedEmail[] = [];
    for (const keys of recipientsPublicKeys) {
      const encryptedKey = await encryptKeysHybrid(encryptionKey, keys, senderPrivateKey);
      const result: HybridEncryptedEmail = {
        recipients: email.recipients,
        sender: email.sender,
        encryptedFor: keys.userID,
        subject: email.subject,
        replyToEmailID: email.replyToEmailID,
        ciphertext,
        encryptedKey,
      };
      encryptedEmails.push(result);
    }

    return encryptedEmails;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(
      new Error(`Failed to encrypt email to multiple recipients with hybrid encryption: ${errorMessage}`),
    );
  }
}

/**
 * Decrypts the email using hybrid encryption.
 *
 * @param encryptedEmail - The encrypted email.
 * @param senderPublicKeys - The public key of the sender.
 * @param recipientPrivateKeys - The private key of the recipient.
 * @returns The decrypted email
 */
export async function decryptEmailHybrid(
  encryptedEmail: HybridEncryptedEmail,
  senderPublicKeys: PublicKeys,
  recipientPrivateKeys: PrivateKeys,
) {
  try {
    const encryptionKey = await decryptKeysHybrid(encryptedEmail.encryptedKey, senderPublicKeys, recipientPrivateKeys);
    const email = await decryptEmailSymmetrically(encryptedEmail, encryptionKey);
    return email;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to decrypt emails with hybrid encryption: ${errorMessage}`));
  }
}
