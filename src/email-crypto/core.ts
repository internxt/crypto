import { HybridEncKey, PwdProtectedKey, PublicKeys, PrivateKeys, EmailBody, EmailBodyEncrypted } from '../types';
import { genSymmetricCryptoKey, encryptSymmetrically, decryptSymmetrically } from '../symmetric-crypto';
import { encapsulateKyber, decapsulateKyber } from '../post-quantum-crypto';
import { deriveWrappingKey, wrapKey, unwrapKey, importWrappingKey } from '../key-wrapper';
import { deriveSecretKey } from '../asymmetric-crypto';
import { getKeyFromPassword, getKeyFromPasswordAndSalt } from '../derive-key';
import { UTF8ToUint8, base64ToUint8Array, uint8ArrayToBase64, uint8ToUTF8, uuidToBytes } from '../utils';

/**
 * Symmetrically encrypts an email with a randomly sampled key.
 *
 * @param email - The email to encrypt.
 * @param aux - The auxiliary data (e.g., email ID or timestamp) for AEAD.
 * @param emailID - The unique identifier of the email.
 * @returns The resulting ciphertext and the used symmetric key
 */
export async function encryptEmailContentSymmetrically(
  email: EmailBody,
  aux: Uint8Array,
  emailID: string,
): Promise<{ enc: EmailBodyEncrypted; encryptionKey: CryptoKey }> {
  try {
    if (!email.text) {
      throw new Error('Invalid input');
    }
    const encryptionKey = await genSymmetricCryptoKey();
    const enc = await encryptEmailContentSymmetricallyWithKey(email, encryptionKey, aux, emailID);
    return { enc, encryptionKey };
  } catch (error) {
    throw new Error('Failed to symmetrically encrypt email', { cause: error });
  }
}

/**
 * Symmetrically encrypts an email with a randomly sampled key.
 *
 * @param email - The email to encrypt.
 * @param subject - The email subject to encrypt.
 * @param aux - The auxiliary data (e.g., email ID or timestamp) for AEAD.
 * @param emailID - The unique identifier of the email.
 * @returns The resulting ciphertext and the used symmetric key
 */
export async function encryptEmailContentAndSubjectSymmetrically(
  email: EmailBody,
  subject: string,
  aux: Uint8Array,
  emailID: string,
): Promise<{ enc: EmailBodyEncrypted; encSubject: string; encryptionKey: CryptoKey }> {
  try {
    if (!subject || !email.text) {
      throw new Error('Invalid input');
    }
    const encryptionKey = await genSymmetricCryptoKey();
    const enc = await encryptEmailContentSymmetricallyWithKey(email, encryptionKey, aux, emailID);
    const subjectBuff = UTF8ToUint8(subject);
    const subjectEnc = await encryptSymmetrically(encryptionKey, subjectBuff, aux);
    const encSubject = uint8ArrayToBase64(subjectEnc);
    return { enc, encSubject, encryptionKey };
  } catch (error) {
    throw new Error('Failed to symmetrically encrypt email and subject', { cause: error });
  }
}

/**
 * Decrypts symmetrically encrypted email.
 *
 * @param encryptedEmail - The email to decrypt.
 * @param encryptionKey - The symmetric CryptoKey.
 * @returns The decrypted email
 */
export async function decryptEmailAndSubjectSymmetrically(
  encryptionKey: CryptoKey,
  aux: Uint8Array,
  encSubject: string,
  enc: EmailBodyEncrypted,
): Promise<{ body: EmailBody; subject: string }> {
  try {
    const array = base64ToUint8Array(encSubject);
    const subjectArray = await decryptSymmetrically(encryptionKey, array, aux);
    const body = await decryptEmailSymmetrically(encryptionKey, aux, enc);
    const subject = uint8ToUTF8(subjectArray);
    return { body, subject };
  } catch (error) {
    throw new Error('Failed to symmetrically decrypt email and subject', { cause: error });
  }
}

/**
 * Symmetrically encrypts an email with a randomly sampled key.
 *
 * @param email - The email to encrypt.
 * @returns The resulting ciphertext and the used symmetric key
 */
export async function encryptEmailContentSymmetricallyWithKey(
  emailBody: EmailBody,
  encryptionKey: CryptoKey,
  aux: Uint8Array,
  emailID: string,
): Promise<EmailBodyEncrypted> {
  try {
    const freeField = uuidToBytes(emailID);
    const text = UTF8ToUint8(emailBody.text);
    const encryptedText = await encryptSymmetrically(encryptionKey, text, aux, freeField);
    const encText = uint8ArrayToBase64(encryptedText);
    const result: EmailBodyEncrypted = { encText };

    if (emailBody.attachments) {
      const encryptedAttachements = await encryptEmailAttachements(emailBody.attachments, encryptionKey, aux, emailID);
      result.encAttachments = encryptedAttachements?.map(uint8ArrayToBase64);
    }
    return result;
  } catch (error) {
    throw new Error('Failed to symmetrically encrypt email with the given key', { cause: error });
  }
}

async function encryptEmailAttachements(
  attachments: string[],
  encryptionKey: CryptoKey,
  aux: Uint8Array,
  emailID: string,
): Promise<Uint8Array[]> {
  try {
    const freeField = uuidToBytes(emailID);
    const encryptedAttachments = await Promise.all(
      attachments.map((attachment) => {
        const binaryAttachment = UTF8ToUint8(attachment);
        return encryptSymmetrically(encryptionKey, binaryAttachment, aux, freeField);
      }),
    );
    return encryptedAttachments;
  } catch (error) {
    throw new Error('Failed to symmetrically encrypt email attachements', { cause: error });
  }
}

async function decryptEmailAttachements(
  encryptedAttachments: Uint8Array[],
  encryptionKey: CryptoKey,
  aux: Uint8Array,
): Promise<Uint8Array[]> {
  try {
    const decryptedAttachments = await Promise.all(
      encryptedAttachments.map((attachment) => {
        return decryptSymmetrically(encryptionKey, attachment, aux);
      }),
    );
    return decryptedAttachments;
  } catch (error) {
    throw new Error('Failed to symmetrically decrypt email attachements', { cause: error });
  }
}

/**
 * Decrypts symmetrically encrypted email.
 *
 * @param encryptedEmail - The email to decrypt.
 * @param encryptionKey - The symmetric CryptoKey.
 * @returns The decrypted email
 */
export async function decryptEmailSymmetrically(
  encryptionKey: CryptoKey,
  aux: Uint8Array,
  enc: EmailBodyEncrypted,
): Promise<EmailBody> {
  try {
    const cipher = base64ToUint8Array(enc.encText);
    const textArray = await decryptSymmetrically(encryptionKey, cipher, aux);
    const text = uint8ToUTF8(textArray);
    const result: EmailBody = { text };

    if (enc.encAttachments) {
      const encAttachements = enc.encAttachments?.map(base64ToUint8Array);
      const attachmentsArray = await decryptEmailAttachements(encAttachements, encryptionKey, aux);
      result.attachments = attachmentsArray?.map((att) => uint8ToUTF8(att));
    }
    return result;
  } catch (error) {
    throw new Error('Failed to symmetrically decrypt email', { cause: error });
  }
}

/**
 * Encrypts the email symmetric key using hybrid encryption.
 *
 * @param emailEncryptionKey - The symmetric CryptoKey used for email encryption.
 * @param recipientPublicKey - The public key of the recipient.
 * @param senderPrivateKey - The private key of the sender.
 * @returns The encrypted email symmetric key
 */
export async function encryptKeysHybrid(
  emailEncryptionKey: CryptoKey,
  recipientPublicKey: PublicKeys,
  senderPrivateKey: PrivateKeys,
): Promise<HybridEncKey> {
  try {
    const eccSecret = await deriveSecretKey(recipientPublicKey.eccPublicKey, senderPrivateKey.eccPrivateKey);
    const { cipherText: kyberCiphertext, sharedSecret: kyberSecret } = encapsulateKyber(
      recipientPublicKey.kyberPublicKey,
    );
    const wrappingKey = await deriveWrappingKey(eccSecret, kyberSecret);
    const encryptedKey = await wrapKey(emailEncryptionKey, wrappingKey);
    const encryptedKeyBase64 = uint8ArrayToBase64(encryptedKey);
    const kyberCiphertextBase64 = uint8ArrayToBase64(kyberCiphertext);

    return { encryptedKey: encryptedKeyBase64, kyberCiphertext: kyberCiphertextBase64 };
  } catch (error) {
    throw new Error('Failed to encrypt email key using hybrid encryption', { cause: error });
  }
}

/**
 * Decrypts the email symmetric key encrypted via hybrid encryption.
 *
 * @param encryptedKey - The encrypted email key.
 * @param senderPublicKey - The public key of the sender.
 * @param recipientPrivateKey - The private key of the recipient.
 * @returns The email encryption CryptoKey
 */
export async function decryptKeysHybrid(
  encryptedKey: HybridEncKey,
  senderPublicKey: PublicKeys,
  recipientPrivateKey: PrivateKeys,
): Promise<CryptoKey> {
  try {
    const kyberCiphertext = base64ToUint8Array(encryptedKey.kyberCiphertext);
    const encKey = base64ToUint8Array(encryptedKey.encryptedKey);
    const eccSecret = await deriveSecretKey(senderPublicKey.eccPublicKey, recipientPrivateKey.eccPrivateKey);
    const kyberSecret = decapsulateKyber(kyberCiphertext, recipientPrivateKey.kyberPrivateKey);
    const wrappingKey = await deriveWrappingKey(eccSecret, kyberSecret);
    const encryptionKey = await unwrapKey(encKey, wrappingKey);
    return encryptionKey;
  } catch (error) {
    throw new Error('Failed to decrypt email key encrypted via hybrid encryption', { cause: error });
  }
}

/**
 * Password-protects the email symmetric key.
 *
 * @param emailEncryptionKey - The symmetric CryptoKey used for email encryption.
 * @param password - The secret password for key protection.
 * @returns The password-protected email symmetric key
 */
export async function passwordProtectKey(emailEncryptionKey: CryptoKey, password: string): Promise<PwdProtectedKey> {
  try {
    const { key, salt } = await getKeyFromPassword(password);
    const wrappingKey = await importWrappingKey(key);
    const encryptedKey = await wrapKey(emailEncryptionKey, wrappingKey);
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
 * @returns The email encryption CryptoKey
 */
export async function removePasswordProtection(
  emailEncryptionKey: PwdProtectedKey,
  password: string,
): Promise<CryptoKey> {
  try {
    const salt = base64ToUint8Array(emailEncryptionKey.salt);
    const encryptedKey = base64ToUint8Array(emailEncryptionKey.encryptedKey);
    const key = await getKeyFromPasswordAndSalt(password, salt);
    const wrappingKey = await importWrappingKey(key);
    const encryptionKey = await unwrapKey(encryptedKey, wrappingKey);
    return encryptionKey;
  } catch (error) {
    throw new Error('Failed to remove password-protection from email key', { cause: error });
  }
}
