import { encryptSymmetrically, decryptSymmetrically } from '../symmetric-crypto';
import { base64ToUint8Array, uint8ArrayToBase64, UTF8ToUint8, mnemonicToBytes } from '../utils';
import { deriveSymmetricCryptoKeyFromContext } from '../derive-key';
import { CONTEXT_KEYSTORE, AES_KEY_BIT_LENGTH, CONTEXT_RECOVERY } from '../constants';
import { getBytesFromData } from '../hash';

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
): Promise<Uint8Array> {
  try {
    const aux = UTF8ToUint8(userID + tag);
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
 * @param userEmail - The ID of the user
 * @param tag - The keystore type-specific tag string
 * @returns The decrypted keystore content
 */
export async function decryptKeystoreContent(
  secretKey: CryptoKey,
  encryptedKeys: Uint8Array,
  userEmail: string,
  tag: string,
): Promise<string> {
  try {
    const aux = UTF8ToUint8(userEmail + tag);
    const content = await decryptSymmetrically(secretKey, encryptedKeys, aux);
    const result = uint8ArrayToBase64(content);
    return result;
  } catch (error) {
    throw new Error('Failed to decrypt keystore content', { cause: error });
  }
}

/**
 * Derives a secret key for protecting the recovery keystore
 *
 * @param recoveryCodes - The recovery codes
 * @returns The derived secret key for protecting the recovery keystore
 */
export async function deriveRecoveryKey(recoveryCodes: string): Promise<CryptoKey> {
  const recoverCodesArray = mnemonicToBytes(recoveryCodes);
  const recoveryCodesBuffer = getBytesFromData(AES_KEY_BIT_LENGTH / 8, recoverCodesArray);
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_RECOVERY, recoveryCodesBuffer);
}

/**
 * Derives a secret key for protecting the keystore
 * 
 * @param baseKey - The base secret key from which a new key secret will be derived
 * @returns The derived secret key for protecting the keystore

*/
export async function deriveEncryptionKeystoreKey(baseKey: Uint8Array): Promise<CryptoKey> {
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_KEYSTORE, baseKey);
}
