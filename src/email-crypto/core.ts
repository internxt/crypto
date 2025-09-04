import { SymmetricCiphertext, HybridEncKey, PwdProtectedKey, PublicKeys, PrivateKeys, EmailBody } from '../types';
import { genSymmetricCryptoKey, encryptSymmetrically, decryptSymmetrically } from '../symmetric-crypto';
import { emailBodyToBinary, binaryToEmailBody } from './converters';
import { encapsulateKyber, decapsulateKyber } from '../post-quantum-crypto';
import { deriveWrappingKey, wrapKey, unwrapKey, importWrappingKey } from '../key-wrapper';
import { deriveSecretKey } from '../asymmetric-crypto';
import { getKeyFromPassword, getKeyFromPasswordAndSalt } from '../derive-key';

/**
 * Symmetrically encrypts an email with a randomly sampled key.
 *
 * @param email - The email to encrypt.
 * @returns The resulting ciphertext and the used symmetric key
 */
export async function encryptEmailContentSymmetrically(
  email: EmailBody,
  aux: string,
  emailID: string,
): Promise<{ enc: SymmetricCiphertext; encryptionKey: CryptoKey }> {
  try {
    const encryptionKey = await genSymmetricCryptoKey();
    const enc = await encryptEmailContentSymmetricallyWithKey(email, encryptionKey, aux, emailID);
    return { enc, encryptionKey };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to symmetrically encrypt email: ${errorMessage}`));
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
  aux: string,
  emailID: string,
): Promise<SymmetricCiphertext> {
  try {
    const binaryEmail = emailBodyToBinary(emailBody);
    const ciphertext = await encryptSymmetrically(encryptionKey, binaryEmail, aux, emailID);
    return ciphertext;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to symmetrically encrypt email with the given key: ${errorMessage}`));
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
  emailCiphertext: SymmetricCiphertext,
  encryptionKey: CryptoKey,
  aux: string,
): Promise<EmailBody> {
  try {
    const binaryEmail = await decryptSymmetrically(encryptionKey, emailCiphertext, aux);
    const body = binaryToEmailBody(binaryEmail);
    return body;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to symmetrically decrypt email: ${errorMessage}`));
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
    return { encryptedKey, kyberCiphertext };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to encrypt email key using hybrid encryption: ${errorMessage}`));
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
    const eccSecret = await deriveSecretKey(senderPublicKey.eccPublicKey, recipientPrivateKey.eccPrivateKey);
    const kyberSecret = decapsulateKyber(encryptedKey.kyberCiphertext, recipientPrivateKey.kyberPrivateKey);
    const wrappingKey = await deriveWrappingKey(eccSecret, kyberSecret);
    const encryptionKey = await unwrapKey(encryptedKey.encryptedKey, wrappingKey);
    return encryptionKey;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to decrypt email key encrypted via hybrid encryption: ${errorMessage}`));
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
    return { encryptedKey, salt };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to password-protect email key: ${errorMessage}`));
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
    const key = await getKeyFromPasswordAndSalt(password, emailEncryptionKey.salt);
    const wrappingKey = await importWrappingKey(key);
    const encryptionKey = await unwrapKey(emailEncryptionKey.encryptedKey, wrappingKey);
    return encryptionKey;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to remove password-protection from email key: ${errorMessage}`));
  }
}
