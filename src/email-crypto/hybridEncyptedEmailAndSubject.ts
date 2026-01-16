import { PublicKeys, PrivateKeys, HybridEncryptedEmail, Email, UserWithPublicKeys } from '../types';
import {
  encryptEmailContentAndSubjectSymmetrically,
  decryptEmailAndSubjectSymmetrically,
  encryptKeysHybrid,
  decryptKeysHybrid,
} from './core';
import { getAuxWithoutSubject } from './utils';

/**
 * Encrypts the email and its subject using hybrid encryption.
 *
 * @param email - The email to encrypt.
 * @param recipientPublicKeys - The public keys of the recipient.
 * @param senderPrivateKey - The private key of the sender.
 * @returns The encrypted email
 */
export async function encryptEmailAndSubjectHybrid(
  email: Email,
  recipient: UserWithPublicKeys,
  senderPrivateKey: PrivateKeys,
): Promise<HybridEncryptedEmail> {
  try {
    const aux = getAuxWithoutSubject(email.params);
    const { enc, encSubject, encryptionKey } = await encryptEmailContentAndSubjectSymmetrically(
      email.body,
      email.params.subject,
      aux,
      email.id,
    );
    const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient.publicKeys, senderPrivateKey);
    const params = { ...email.params, subject: encSubject };
    return { enc, encryptedKey, recipientEmail: recipient.email, params, id: email.id };
  } catch (error) {
    throw new Error('Failed to encrypt the email and its subject with hybrid encryption', { cause: error });
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
export async function encryptEmailAndSubjectHybridForMultipleRecipients(
  email: Email,
  recipients: UserWithPublicKeys[],
  senderPrivateKey: PrivateKeys,
): Promise<HybridEncryptedEmail[]> {
  try {
    const aux = getAuxWithoutSubject(email.params);
    const { enc, encSubject, encryptionKey } = await encryptEmailContentAndSubjectSymmetrically(
      email.body,
      email.params.subject,
      aux,
      email.id,
    );

    const encryptedEmails: HybridEncryptedEmail[] = [];
    for (const recipient of recipients) {
      const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient.publicKeys, senderPrivateKey);
      const params = { ...email.params, subject: encSubject };
      encryptedEmails.push({ enc, encryptedKey, recipientEmail: recipient.email, params, id: email.id });
    }
    return encryptedEmails;
  } catch (error) {
    throw new Error('Failed to encrypt the email and its subject to multiple recipients with hybrid encryption', {
      cause: error,
    });
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
export async function decryptEmailAndSubjectHybrid(
  encryptedEmail: HybridEncryptedEmail,
  senderPublicKeys: PublicKeys,
  recipientPrivateKeys: PrivateKeys,
): Promise<Email> {
  try {
    const aux = getAuxWithoutSubject(encryptedEmail.params);
    const encryptionKey = await decryptKeysHybrid(encryptedEmail.encryptedKey, senderPublicKeys, recipientPrivateKeys);
    const { body, subject } = await decryptEmailAndSubjectSymmetrically(
      encryptionKey,
      aux,
      encryptedEmail.params.subject,
      encryptedEmail.enc,
    );
    const params = { ...encryptedEmail.params, subject };
    return { body, params, id: encryptedEmail.id };
  } catch (error) {
    throw new Error('Failed to decrypt the email and its subject with hybrid encryption', { cause: error });
  }
}
