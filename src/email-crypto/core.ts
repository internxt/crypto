import { HybridEncKey, PwdProtectedKey, EmailBody, EmailBodyEncrypted, RecipientWithPublicKey } from '../types';
import { encryptSymmetrically, decryptSymmetrically, genSymmetricKey } from '../symmetric-crypto';
import { encapsulateHybrid, decapsulateHybrid } from '../hybrid-crypto';
import { wrapKey, unwrapKey } from '../key-wrapper';
import { getKeyFromPassword, getKeyFromPasswordAndSalt } from '../derive-key';
import { UTF8ToUint8, base64ToUint8Array, uint8ArrayToBase64, uint8ToUTF8 } from '../utils';

/**
 * Symmetrically encrypts email body.
 *
 * @param body - The email body to encrypt.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The resulting encrypted email body and symmetric key used for encryption
 */
export async function encryptEmailBody(
  body: EmailBody,
  aux?: Uint8Array,
): Promise<{
  encEmailBody: EmailBodyEncrypted;
  encryptionKey: Uint8Array;
}> {
  try {
    if (!body.text || !body.subject) {
      throw new Error('Invalid input');
    }
    const encryptionKey = genSymmetricKey();
    const encEmailBody = await encryptEmailBodyWithKey(body, encryptionKey, aux);

    return { encEmailBody, encryptionKey };
  } catch (error) {
    throw new Error('Failed to symmetrically encrypt email body', { cause: error });
  }
}

/**
 * Symmetrically encrypts email body with the given key.
 *
 * @param body - The email body to encrypt.
 * @param encryptionKey - The symmetric key to encrypt the email.
 * @param aux -  An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The resulting encrypted email body and symmetric key used for encryption
 */
export async function encryptEmailBodyWithKey(
  body: EmailBody,
  encryptionKey: Uint8Array,
  aux?: Uint8Array,
): Promise<EmailBodyEncrypted> {
  try {
    const text = UTF8ToUint8(body.text);
    const subject = UTF8ToUint8(body.subject);
    const subjectEnc = await encryptSymmetrically(encryptionKey, subject, aux);
    const encryptedText = await encryptSymmetrically(encryptionKey, text, aux);
    const encText = uint8ArrayToBase64(encryptedText);
    const encSubject = uint8ArrayToBase64(subjectEnc);
    const enc: EmailBodyEncrypted = { encText, encSubject };

    if (body.attachments) {
      const encryptedAttachments = await Promise.all(
        body.attachments.map((attachment) => {
          const binaryAttachment = UTF8ToUint8(attachment);
          return encryptSymmetrically(encryptionKey, binaryAttachment, aux);
        }),
      );
      enc.encAttachments = encryptedAttachments?.map(uint8ArrayToBase64);
    }

    return enc;
  } catch (error) {
    throw new Error('Failed to encrypt email body', { cause: error });
  }
}

/**
 * Decrypts symmetrically encrypted email body.
 *
 * @param encEmailBody - The email body to decrypt.
 * @param encryptionKey - The symmetric key to decrypt the email.
 * @param aux - An optional auxilary sting for AEAD (e.g., email ID or timestamp).
 * @returns The resulting decrypted email body
 */
export async function decryptEmailBody(
  encEmailBody: EmailBodyEncrypted,
  encryptionKey: Uint8Array,
  aux?: Uint8Array,
): Promise<EmailBody> {
  try {
    const encSubject = base64ToUint8Array(encEmailBody.encSubject);
    const subjectArray = await decryptSymmetrically(encryptionKey, encSubject, aux);
    const subject = uint8ToUTF8(subjectArray);
    const encText = base64ToUint8Array(encEmailBody.encText);
    const textArray = await decryptSymmetrically(encryptionKey, encText, aux);
    const text = uint8ToUTF8(textArray);
    const body: EmailBody = { text, subject };

    if (encEmailBody.encAttachments) {
      const encAttachments = encEmailBody.encAttachments?.map(base64ToUint8Array);
      const decryptedAttachments = await Promise.all(
        encAttachments.map((attachment) => {
          return decryptSymmetrically(encryptionKey, attachment, aux);
        }),
      );
      body.attachments = decryptedAttachments?.map((att) => uint8ToUTF8(att));
    }

    return body;
  } catch (error) {
    throw new Error('Failed to symmetrically decrypt email body', { cause: error });
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
    throw new Error('Failed to encrypt email key using hybrid encryption', { cause: error });
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
    throw new Error('Failed to decrypt email key encrypted via hybrid encryption', { cause: error });
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
    throw new Error('Failed to password-protect email key', { cause: error });
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
    throw new Error('Failed to remove password-protection from email key', { cause: error });
  }
}
