import { PublicKeys, PrivateKeys, HybridEncryptedEmail, Email, UserWithPublicKeys } from '../types';
import {
  encryptEmailContentSymmetrically,
  decryptEmailSymmetrically,
  encryptKeysHybrid,
  decryptKeysHybrid,
} from './core';
import { getAux } from './utils';

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
  recipient: UserWithPublicKeys,
  senderPrivateKey: PrivateKeys,
): Promise<HybridEncryptedEmail> {
  try {
    const aux = getAux(email.params);
    const { enc, encryptionKey } = await encryptEmailContentSymmetrically(email.body, aux, email.params.id);
    const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient.publicKeys, senderPrivateKey);
    return { enc, encryptedKey, recipientID: recipient.id, params: email.params };
  } catch (error) {
    throw new Error('Failed to encrypt email with hybrid encryption', { cause: error });
  }
}

/**
 * Encrypts the email using hybrid encryption for multiple recipients.
 *
 * @param email - The email to encrypt.
 * @param recipients - The recipients with corresponding public keys.
 * @param senderPrivateKey - The private key of the sender.
 * @returns The set of encrypted email
 */
export async function encryptEmailHybridForMultipleRecipients(
  email: Email,
  recipients: UserWithPublicKeys[],
  senderPrivateKey: PrivateKeys,
): Promise<HybridEncryptedEmail[]> {
  try {
    const aux = getAux(email.params);
    const { enc, encryptionKey } = await encryptEmailContentSymmetrically(email.body, aux, email.params.id);

    const encryptedEmails: HybridEncryptedEmail[] = [];
    for (const recipient of recipients) {
      const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient.publicKeys, senderPrivateKey);
      encryptedEmails.push({ enc, encryptedKey, recipientID: recipient.id, params: email.params });
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
): Promise<Email> {
  try {
    const aux = getAux(encryptedEmail.params);
    const encryptionKey = await decryptKeysHybrid(encryptedEmail.encryptedKey, senderPublicKeys, recipientPrivateKeys);
    const body = await decryptEmailSymmetrically(encryptedEmail.enc, encryptionKey, aux);
    return { body, params: encryptedEmail.params };
  } catch (error) {
    throw new Error('Failed to decrypt email with hybrid encryption', { cause: error });
  }
}
