import {
  PublicKeys,
  PrivateKeys,
  HybridEncryptedEmail,
  Email,
  UserWithPublicKeys,
  EmailBody,
  EmailBodyEncrypted,
} from '../types';
import {
  encryptEmailContentSymmetrically,
  decryptEmailSymmetrically,
  encryptEmailContentAndSubjectSymmetrically,
  decryptEmailAndSubjectSymmetrically,
  encryptKeysHybrid,
  decryptKeysHybrid,
} from './core';
import { getAux } from './utils';

async function encryptEmailBody(email: Email, isSubjectEncrypted: boolean) {
  try {
    const aux = getAux(email.params, isSubjectEncrypted);

    let enc: EmailBodyEncrypted;
    let encryptionKey: CryptoKey;
    let params = email.params;

    if (isSubjectEncrypted) {
      const result = await encryptEmailContentAndSubjectSymmetrically(email.body, email.params.subject, aux, email.id);
      enc = result.enc;
      encryptionKey = result.encryptionKey;
      params = { ...email.params, subject: result.encSubject };
    } else {
      const result = await encryptEmailContentSymmetrically(email.body, aux, email.id);
      enc = result.enc;
      encryptionKey = result.encryptionKey;
    }

    return { encryptionKey, enc, params };
  } catch (error) {
    throw new Error('Failed to encrypt email body', { cause: error });
  }
}

/**
 * Encrypts the email using hybrid encryption.
 *
 * @param email - The email to encrypt.
 * @param recipientPublicKeys - The public keys of the recipient.
 * @param senderPrivateKey - The private key of the sender.
 * @param isSubjectEncrypted -  Indicates if the email subject field should be encrypted
 * @returns The encrypted email
 */
export async function encryptEmailHybrid(
  email: Email,
  recipient: UserWithPublicKeys,
  senderPrivateKey: PrivateKeys,
  isSubjectEncrypted: boolean = false,
): Promise<HybridEncryptedEmail> {
  try {
    const { encryptionKey, params, enc } = await encryptEmailBody(email, isSubjectEncrypted);
    const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient.publicKeys, senderPrivateKey);
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
 * @param senderPrivateKey - The private key of the sender.
 * @param isSubjectEncrypted -  Indicates if the email subject field should be encrypted
 * @returns The set of encrypted email
 */
export async function encryptEmailHybridForMultipleRecipients(
  email: Email,
  recipients: UserWithPublicKeys[],
  senderPrivateKey: PrivateKeys,
  isSubjectEncrypted: boolean = false,
): Promise<HybridEncryptedEmail[]> {
  try {
    const { encryptionKey, params, enc } = await encryptEmailBody(email, isSubjectEncrypted);

    const encryptedEmails: HybridEncryptedEmail[] = [];
    for (const recipient of recipients) {
      const encryptedKey = await encryptKeysHybrid(encryptionKey, recipient.publicKeys, senderPrivateKey);
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
    const isSubjectEncrypted = encryptedEmail.isSubjectEncrypted;
    const aux = getAux(encryptedEmail.params, isSubjectEncrypted);
    const encryptionKey = await decryptKeysHybrid(encryptedEmail.encryptedKey, senderPublicKeys, recipientPrivateKeys);

    let body: EmailBody;
    let params = encryptedEmail.params;
    if (isSubjectEncrypted) {
      const result = await decryptEmailAndSubjectSymmetrically(
        encryptionKey,
        aux,
        encryptedEmail.params.subject,
        encryptedEmail.enc,
      );
      body = result.body;
      params = { ...encryptedEmail.params, subject: result.subject };
    } else {
      body = await decryptEmailSymmetrically(encryptionKey, aux, encryptedEmail.enc);
    }

    return { body, params, id: encryptedEmail.id };
  } catch (error) {
    throw new Error('Failed to decrypt email with hybrid encryption', { cause: error });
  }
}
