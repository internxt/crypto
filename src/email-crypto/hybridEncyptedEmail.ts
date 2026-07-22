import { Email, RecipientWithPublicKey, HybridEncKey, EmailEncrypted } from '../types';
import { decryptEmail, decryptPreview, encryptKeysHybrid, decryptKeysHybrid, encryptEmail } from './core';
import {
  InvalidInputEmail,
} from './errors';

/**
 * Encrypts the email using hybrid encryption for multiple recipients.
 *
 * @param email - The email to encrypt for multiple recipients.
 * @param recipients - The recipients with corresponding public keys.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The set of encrypted keys (one per user) and encrypted email
 */
export async function encryptEmailHybridForMultipleRecipients(
  email: Email,
  recipients: RecipientWithPublicKey[],
  aux?: Uint8Array,
): Promise<{ encryptedKeys: HybridEncKey[]; encEmail: EmailEncrypted }> {
    if (!recipients || recipients.length === 0) {
      throw new InvalidInputEmail();
    }
    const { encryptionKey, encEmail } = await encryptEmail(email, aux);

    const encryptedKeys = await Promise.all(recipients.map((recipient) => encryptKeysHybrid(encryptionKey, recipient)));

    return { encryptedKeys, encEmail };
}

/**
 * Decrypts the email using hybrid encryption.
 *
 * @param encEmail - The encrypted email.
 * @param encryptedKey - The encrypted key for this recipient.
 * @param recipientPrivateHybridKeys - The private key of the recipient.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The decrypted email
 */
export async function decryptEmailHybrid(
  encEmail: EmailEncrypted,
  encryptedKey: HybridEncKey,
  recipientPrivateHybridKeys: Uint8Array,
  aux?: Uint8Array,
): Promise<Email> {
    const encryptionKey = await decryptKeysHybrid(encryptedKey, recipientPrivateHybridKeys);
    return await decryptEmail(encEmail, encryptionKey, aux);
}

export async function decryptEmailPreviewHybrid(
  encPreview: string,
  encryptedKey: HybridEncKey,
  recipientPrivateHybridKeys: Uint8Array,
  aux?: Uint8Array,
): Promise<{ preview: string; encryptionKey: Uint8Array }> {
    const encryptionKey = await decryptKeysHybrid(encryptedKey, recipientPrivateHybridKeys);
    const preview = await decryptPreview(encPreview, encryptionKey, aux);
    return { preview, encryptionKey };
}
