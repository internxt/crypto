import { encryptSymmetrically, decryptSymmetrically } from '../symmetric-crypto';
import { base64ToUint8Array, uint8ArrayToBase64 } from '../utils';
import { SymmetricCiphertext } from '../types';
import sessionStorageService from '../storage-service/sessionStorageService';
import { deriveSymmetricCryptoKeyFromContext } from '../derive-key';
import { CONTEXT_LOGIN, CONTEXT_ENC_KEYSTORE, AES_KEY_BIT_LENGTH, CONTEXT_RECOVERY } from '../constants';
import { getBitsFromString } from '../hash';

/**
 * Encrypts the keystore content using symmetric encryption
 *
 * @param secretKey - The symmetric key to encrypt the keystore content
 * @param content - The content of the keystore
 * @param userID - The ID of the user
 * @param tag - The keystore type-specific tag string
 * @returns The encrypted keystore content
 */
export async function encryptKeystoreContent(
  secretKey: CryptoKey,
  content: string,
  userID: string,
  tag: string,
): Promise<SymmetricCiphertext> {
  try {
    const aux = userID + tag;
    const message = base64ToUint8Array(content);
    const result = await encryptSymmetrically(secretKey, message, aux);
    return result;
  } catch (error) {
    throw new Error('Failed to encrypt keystore content', { cause: error });
  }
}

/**
 * Decrypts the keystore content using symmetric encryption
 *
 * @param secretKey - The symmetric key to decrypt the keystore content
 * @param encryptedKeys - The encrypted keystore content
 * @param userID - The ID of the user
 * @param tag - The keystore type-specific tag string
 * @returns The decrypted keystore content
 */
export async function decryptKeystoreContent(
  secretKey: CryptoKey,
  encryptedKeys: SymmetricCiphertext,
  userID: string,
  tag: string,
): Promise<string> {
  try {
    const aux = userID + tag;
    const content = await decryptSymmetrically(secretKey, encryptedKeys, aux);
    const result = uint8ArrayToBase64(content);
    return result;
  } catch (error) {
    throw new Error('Failed to decrypt keystore content', { cause: error });
  }
}

/**
 * Gets User ID from the session storage
 *
 * @returns The ID of the user
 */
export function getUserID(): string {
  try {
    const userID = sessionStorageService.get('userID');
    if (!userID) {
      throw new Error('No UserID');
    }
    return userID;
  } catch (error) {
    throw new Error('Failed to get UserID from session storage', { cause: error });
  }
}

/**
 * Gets user's base key from the session storage
 *
 * @returns The user's base key
 */
export function getBaseKey(): Uint8Array {
  try {
    const baseKeyBase64 = sessionStorageService.get('baseKey');
    if (!baseKeyBase64) {
      throw new Error('No base key');
    }
    return base64ToUint8Array(baseKeyBase64);
  } catch (error) {
    throw new Error('Failed to get base key from session storage', { cause: error });
  }
}

/**
 * Derives a secret key for protecting the idenity keystore
 *
 * @param baseKey - The base secret key from which a new key secret will be derived
 * @returns The derived secret key for protecting the idenity keystore
 */
export async function deriveIdentityKeystoreKey(baseKey: Uint8Array): Promise<CryptoKey> {
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_LOGIN, baseKey);
}

/**
 * Derives a secret key for protecting the recovery keystore
 *
 * @param recoveryCodes - The recovery codes
 * @returns The derived secret key for protecting the recovery keystore
 */
export async function deriveRecoveryKey(recoveryCodes: string): Promise<CryptoKey> {
  const recoveryCodesBuffer = await getBitsFromString(AES_KEY_BIT_LENGTH, recoveryCodes);
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_RECOVERY, recoveryCodesBuffer);
}

/**
 * Derives a secret key for protecting the encryption keystore
 * 
 * @param baseKey - The base secret key from which a new key secret will be derived
 * @returns The derived secret key for protecting the encryption keystore

*/
export async function deriveEncryptionKeystoreKey(baseKey: Uint8Array): Promise<CryptoKey> {
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_ENC_KEYSTORE, baseKey);
}
