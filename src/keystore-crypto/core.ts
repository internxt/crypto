import { encryptSymmetrically, decryptSymmetrically } from '../symmetric-crypto';
import { base64ToUint8Array, uint8ArrayToBase64, UTF8ToUint8, mnemonicToBytes } from '../utils';
import { deriveSymmetricKeyFromContext } from '../derive-key';
import { CONTEXT_ENC_KEYSTORE, AES_KEY_BIT_LENGTH, CONTEXT_RECOVERY } from '../constants';
import { getBytesFromData } from '../hash';
import { EncryptedKeystore, HybridKeyPair, KeystoreType } from '../types';

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
  secretKey: Uint8Array,
  keys: HybridKeyPair,
  userEmail: string,
  type: KeystoreType,
): Promise<EncryptedKeystore> {
  try {
    const aux = UTF8ToUint8(userEmail + type);
    const publicKey = uint8ArrayToBase64(keys.publicKey);
    const secretKeyEncrypted = await encryptSymmetrically(secretKey, keys.secretKey, aux);

    const keystore: EncryptedKeystore = {
      userEmail,
      type,
      publicKey,
      privateKeyEncrypted: uint8ArrayToBase64(secretKeyEncrypted),
    };
    return keystore;
  } catch (error) {
    throw new Error('Failed to encrypt keystore content', { cause: error });
  }
}

/**
 * Decrypts the keystore content using symmetric encryption
 *
 * @param kesytoreOpeningKey - The symmetric key to decrypt the keystore content
 * @param encryptedKeys - The encrypted keystore content
 * @param userEmail - The ID of the user
 * @param tag - The keystore type-specific tag string
 * @returns The decrypted keystore content
 */
export async function decryptKeystoreContent(
  kesytoreOpeningKey: Uint8Array,
  encryptedKeystore: EncryptedKeystore,
): Promise<HybridKeyPair> {
  try {
    const aux = UTF8ToUint8(encryptedKeystore.userEmail + encryptedKeystore.type);
    const publicKey = base64ToUint8Array(encryptedKeystore.publicKey);
    const ciphertext = base64ToUint8Array(encryptedKeystore.privateKeyEncrypted);
    const secretKey = await decryptSymmetrically(kesytoreOpeningKey, ciphertext, aux);
    return {
      publicKey,
      secretKey,
    };
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
export async function deriveRecoveryKey(recoveryCodes: string): Promise<Uint8Array> {
  const recoverCodesArray = mnemonicToBytes(recoveryCodes);
  const recoveryCodesBuffer = getBytesFromData(AES_KEY_BIT_LENGTH / 8, recoverCodesArray);
  return deriveSymmetricKeyFromContext(CONTEXT_RECOVERY, recoveryCodesBuffer);
}

/**
 * Derives a secret key for protecting the encryption keystore
 *
 * @param baseKey - The base secret key from which a new key secret will be derived
 * @returns The derived secret key for protecting the encryption keystore
 */
export async function deriveEncryptionKeystoreKey(baseKey: Uint8Array): Promise<Uint8Array> {
  return deriveSymmetricKeyFromContext(CONTEXT_ENC_KEYSTORE, baseKey);
}
