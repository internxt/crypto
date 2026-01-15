import { HybridEncKey, PwdProtectedKey, PublicKeys, PrivateKeys, EmailBody } from '../types';
import { genSymmetricCryptoKey, encryptSymmetrically, decryptSymmetrically } from '../symmetric-crypto';
import { emailBodyToBinary, binaryToEmailBody } from './converters';
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
): Promise<{ enc: Uint8Array; encryptionKey: CryptoKey }> {
  try {
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
): Promise<{ enc: Uint8Array; subjectEnc: Uint8Array; encryptionKey: CryptoKey }> {
  try {
    const encryptionKey = await genSymmetricCryptoKey();
    const enc = await encryptEmailContentSymmetricallyWithKey(email, encryptionKey, aux, emailID);
    const subjectBuff = UTF8ToUint8(subject);
    const subjectEnc = await encryptSymmetrically(encryptionKey, subjectBuff, aux);
    return { enc, encryptionKey, subjectEnc };
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
  emailCiphertext: Uint8Array,
  encSubject: Uint8Array,
  encryptionKey: CryptoKey,
  aux: Uint8Array,
): Promise<{ body: EmailBody; subject: string }> {
  try {
    const binaryEmail = await decryptSymmetrically(encryptionKey, emailCiphertext, aux);
    const subject = await decryptSymmetrically(encryptionKey, encSubject, aux);
    const body = binaryToEmailBody(binaryEmail);
    return { body, subject: uint8ToUTF8(subject) };
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
): Promise<Uint8Array> {
  try {
    const freeField = uuidToBytes(emailID);
    const binaryEmail = emailBodyToBinary(emailBody);
    const ciphertext = await encryptSymmetrically(encryptionKey, binaryEmail, aux, freeField);
    return ciphertext;
  } catch (error) {
    throw new Error('Failed to symmetrically encrypt email with the given key', { cause: error });
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
  emailCiphertext: Uint8Array,
  encryptionKey: CryptoKey,
  aux: Uint8Array,
): Promise<EmailBody> {
  try {
    const binaryEmail = await decryptSymmetrically(encryptionKey, emailCiphertext, aux);
    const body = binaryToEmailBody(binaryEmail);
    return body;
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
