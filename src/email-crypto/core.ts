import { HybridEncKey, PwdProtectedKey, Email, RecipientWithPublicKey, EmailEncrypted } from '../types';
import { encryptSymmetrically, decryptSymmetrically, genSymmetricKey } from '../symmetric-crypto';
import { encapsulateHybrid, decapsulateHybrid } from '../hybrid-crypto';
import { wrapKey, unwrapKey } from '../key-wrapper';
import { getKeyFromPassword, getKeyFromPasswordAndSalt } from '../derive-password';
import { UTF8ToUint8, base64ToUint8Array, uint8ArrayToBase64, uint8ToUTF8 } from '../utils';
import {
  EmailHybridDecryptionError,
  EmailHybridEncryptionError,
  InvalidInputEmail,
  EmailSymmetricDecryptionError,
  EmailSymmetricEncryptionError,
  EmailPasswordOpenError,
  EmailPasswordProtectError,
  EmailPreviewSymmetricDecryptionError,
} from './errors';

/**
 * Symmetrically encrypts email.
 *
 * @param email - The email to encrypt.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The resulting encrypted email and symmetric key used for encryption
 */
export async function encryptEmail(
  email: Email,
  aux?: Uint8Array,
): Promise<{
  encEmail: EmailEncrypted;
  encryptionKey: Uint8Array;
}> {
  if (!email.text) {
    throw new InvalidInputEmail();
  }
  try {
    const encryptionKey = genSymmetricKey();
    const encEmail = await encryptEmailWithKey(email, encryptionKey, aux);

    return { encEmail, encryptionKey };
  } catch (error) {
    throw new EmailSymmetricEncryptionError(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Symmetrically encrypts email with the given key.
 *
 * @param email - The email to encrypt.
 * @param encryptionKey - The symmetric key to encrypt the email.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The resulting encrypted email and symmetric key used for encryption
 */
export async function encryptEmailWithKey(
  email: Email,
  encryptionKey: Uint8Array,
  aux?: Uint8Array,
): Promise<EmailEncrypted> {
  try {
    const text = UTF8ToUint8(email.text);
    const preview = UTF8ToUint8(email.preview);

    const encryptedText = await encryptSymmetrically(encryptionKey, text, aux);
    const encText = uint8ArrayToBase64(encryptedText);

    const encryptedPreview = await encryptSymmetrically(encryptionKey, preview, aux);
    const encPreview = uint8ArrayToBase64(encryptedPreview);

    const encryptedAttachmentsSessionKey = await encryptSymmetrically(encryptionKey, email.attachmentsSessionKey, aux);
    const encAttachmentsSessionKey = uint8ArrayToBase64(encryptedAttachmentsSessionKey);

    return { encText, encPreview, encAttachmentsSessionKey };
  } catch (error) {
    throw new EmailSymmetricEncryptionError(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Decrypts symmetrically encrypted email preview.
 *
 * @param encEmailPreview - The email preview to decrypt.
 * @param encryptionKey - The symmetric key to decrypt the email.
 * @param aux - An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The resulting decrypted email
 */
export async function decryptPreview(
  encEmailPreview: string,
  encryptionKey: Uint8Array,
  aux?: Uint8Array,
): Promise<string> {
  try {

    const encPreview = base64ToUint8Array(encEmailPreview);
    const previewArray = await decryptSymmetrically(encryptionKey, encPreview, aux);
    const preview = uint8ToUTF8(previewArray);

    return preview;
  } catch (error) {
    throw new EmailPreviewSymmetricDecryptionError(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Decrypts symmetrically encrypted email.
 *
 * @param encEmail - The email to decrypt.
 * @param encryptionKey - The symmetric key to decrypt the email.
 * @param aux - An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The resulting decrypted email
 */
export async function decryptEmail(
  encEmail: EmailEncrypted,
  encryptionKey: Uint8Array,
  aux?: Uint8Array,
): Promise<Email> {
  try {
    const encText = base64ToUint8Array(encEmail.encText);
    const textArray = await decryptSymmetrically(encryptionKey, encText, aux);
    const text = uint8ToUTF8(textArray);

    const encPreview = base64ToUint8Array(encEmail.encPreview);
    const previewArray = await decryptSymmetrically(encryptionKey, encPreview, aux);
    const preview = uint8ToUTF8(previewArray);

    const encAttachementSessionKey = base64ToUint8Array(encEmail.encAttachmentsSessionKey);
    const attachmentsSessionKey = await decryptSymmetrically(encryptionKey, encAttachementSessionKey, aux);

    return { text, preview, attachmentsSessionKey };
  } catch (error) {
    throw new EmailSymmetricDecryptionError(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Encrypts the email symmetric key using hybrid encryption.
 *
 * @param emailEncryptionKey - The symmetric key used for email encryption.
 * @param recipient - The recipient with a public hybrid key.
 * @returns The encrypted email symmetric key
 */
export async function encryptKeysHybrid(
  emailEncryptionKey: Uint8Array,
  recipient: RecipientWithPublicKey,
): Promise<HybridEncKey> {
  try {
    const { cipherText, sharedSecret } = encapsulateHybrid(recipient.publicHybridKey);
    const encryptedKey = await wrapKey(emailEncryptionKey, sharedSecret);
    const encryptedKeyBase64 = uint8ArrayToBase64(encryptedKey);
    const kyberCiphertextBase64 = uint8ArrayToBase64(cipherText);

    return {
      encryptedKey: encryptedKeyBase64,
      hybridCiphertext: kyberCiphertextBase64,
      encryptedForEmail: recipient.email,
    };
  } catch (error) {
    throw new EmailHybridEncryptionError(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Decrypts the email symmetric key encrypted via hybrid encryption.
 *
 * @param encryptedKey - The encrypted email key.
 * @param recipientPrivateKey - The private key of the recipient.
 * @returns The email encryption key
 */
export async function decryptKeysHybrid(
  encryptedKey: HybridEncKey,
  recipientPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  try {
    const kyberCiphertext = base64ToUint8Array(encryptedKey.hybridCiphertext);
    const encKey = base64ToUint8Array(encryptedKey.encryptedKey);
    const sharedSecret = decapsulateHybrid(kyberCiphertext, recipientPrivateKey);
    const encryptionKey = await unwrapKey(encKey, sharedSecret);
    return encryptionKey;
  } catch (error) {
    throw new EmailHybridDecryptionError(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Password-protects the email symmetric key.
 *
 * @param emailEncryptionKey - The symmetric key used for email encryption.
 * @param password - The secret password for key protection.
 * @returns The password-protected email symmetric key
 */
export async function passwordProtectKey(emailEncryptionKey: Uint8Array, password: string): Promise<PwdProtectedKey> {
  try {
    const { key, salt } = await getKeyFromPassword(password);
    const encryptedKey = await wrapKey(emailEncryptionKey, key);
    const saltStr = uint8ArrayToBase64(salt);
    const encryptedKeyStr = uint8ArrayToBase64(encryptedKey);
    return { encryptedKey: encryptedKeyStr, salt: saltStr };
  } catch (error) {
    throw new EmailPasswordProtectError(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Removes passoword-protection and exposes the email symmetric key.
 *
 * @param emailEncryptionKey -  The password-protected email key.
 * @param password - The secret password for key protection.
 * @returns The email encryption key
 */
export async function removePasswordProtection(
  emailEncryptionKey: PwdProtectedKey,
  password: string,
): Promise<Uint8Array> {
  try {
    const salt = base64ToUint8Array(emailEncryptionKey.salt);
    const encryptedKey = base64ToUint8Array(emailEncryptionKey.encryptedKey);
    const key = await getKeyFromPasswordAndSalt(password, salt);
    const encryptionKey = await unwrapKey(encryptedKey, key);
    return encryptionKey;
  } catch (error) {
    throw new EmailPasswordOpenError(error instanceof Error ? error.message : String(error));
  }
}
