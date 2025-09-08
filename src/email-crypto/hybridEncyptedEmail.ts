import { PublicKeys, PrivateKeys, HybridEncryptedEmail, EmailBody, UserWithPublicKeys } from '../types';
import {
  encryptEmailContentSymmetrically,
  decryptEmailSymmetrically,
  encryptKeysHybrid,
  decryptKeysHybrid,
} from './core';

/**
 * Encrypts the email using hybrid encryption.
 *
 * @param email - The email to encrypt.
 * @param recipientPublicKeys - The public keys of the recipient.
 * @param senderPrivateKey - The private key of the sender.
 * @returns The encrypted email
 */
export async function encryptEmailHybrid(
  email: EmailBody,
  recipient: UserWithPublicKeys,
  senderPrivateKey: PrivateKeys,
  aux: string,
  emailID: string,
): Promise<HybridEncryptedEmail> {
  try {
    const { enc, encryptionKey } = await encryptEmailContentSymmetrically(email, aux, emailID);
    const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient.publicKeys, senderPrivateKey);
    return { enc, encryptedKey, recipientID: recipient.id };
  } catch (error) {
    throw new Error('Failed to encrypt email with hybrid encryption', { cause: error });
  }
}

/**
 * Encrypts the email using hybrid encryption for multiple recipients.
 *
 * @param email - The email body to encrypt.
 * @param recipients - The recipients with corresponding public keys.
 * @param senderPrivateKey - The private key of the sender.
 * @param aux - The auxilary string.
 * @param emailID - The ID of the email.
 * @returns The set of encrypted email
 */
export async function encryptEmailHybridForMultipleRecipients(
  email: EmailBody,
  recipients: UserWithPublicKeys[],
  senderPrivateKey: PrivateKeys,
  aux: string,
  emailID: string,
): Promise<HybridEncryptedEmail[]> {
  try {
    const { enc, encryptionKey } = await encryptEmailContentSymmetrically(email, aux, emailID);

    const encryptedEmails: HybridEncryptedEmail[] = [];
    for (const recipient of recipients) {
      const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient.publicKeys, senderPrivateKey);
      encryptedEmails.push({ enc, encryptedKey, recipientID: recipient.id });
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
 * @param senderPublicKeys - The public key of the sender.
 * @param recipientPrivateKeys - The private key of the recipient.
 * @returns The decrypted email
 */
export async function decryptEmailHybrid(
  encryptedEmail: HybridEncryptedEmail,
  senderPublicKeys: PublicKeys,
  recipientPrivateKeys: PrivateKeys,
  aux: string,
) {
  try {
    const encryptionKey = await decryptKeysHybrid(encryptedEmail.encryptedKey, senderPublicKeys, recipientPrivateKeys);
    const email = await decryptEmailSymmetrically(encryptedEmail.enc, encryptionKey, aux);
    return email;
  } catch (error) {
    throw new Error('Failed to decrypt emails with hybrid encryption', { cause: error });
  }
}
