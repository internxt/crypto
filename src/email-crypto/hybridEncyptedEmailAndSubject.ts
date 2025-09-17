import { ciphertextToBase64, base64ToCiphertext } from '../utils';
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
    const { enc, encryptionKey, subjectEnc } = await encryptEmailContentAndSubjectSymmetrically(
      email.body,
      email.params.subject,
      aux,
      email.params.id,
    );
    const encSubjectStr = ciphertextToBase64(subjectEnc);
    const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient.publicKeys, senderPrivateKey);
    const params = { ...email.params, subject: encSubjectStr };
    return { enc, encryptedKey, recipientID: recipient.id, params };
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
    const { enc, encryptionKey, subjectEnc } = await encryptEmailContentAndSubjectSymmetrically(
      email.body,
      email.params.subject,
      aux,
      email.params.id,
    );
    const encSubjectStr = ciphertextToBase64(subjectEnc);

    const encryptedEmails: HybridEncryptedEmail[] = [];
    for (const recipient of recipients) {
      const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient.publicKeys, senderPrivateKey);
      const params = { ...email.params, subject: encSubjectStr };
      encryptedEmails.push({ enc, encryptedKey, recipientID: recipient.id, params });
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
    const encSubject = base64ToCiphertext(encryptedEmail.params.subject);
    const { body, subject } = await decryptEmailAndSubjectSymmetrically(
      encryptedEmail.enc,
      encSubject,
      encryptionKey,
      aux,
    );
    const params = { ...encryptedEmail.params, subject };
    return { body, params };
  } catch (error) {
    throw new Error('Failed to decrypt the email and its subject with hybrid encryption', { cause: error });
  }
}
