import { EncryptionKeys, EncryptedKeystore, KeystoreType, genMnemonic } from '../utils';
import {
  ENCRYPTION_KEYSTORE_TAG,
  RECOVERY_KEYSTORE_TAG,
  CONTEXT_ENC_KEYSTORE,
  AES_KEY_BIT_LENGTH,
  CONTEXT_RECOVERY,
} from '../constants';
import { createKeystore, openKeystore, getUserID, getBaseKey } from './core';
import { encryptionKeysToBase64, base64ToEncryptionKeys } from './converters';
import { generateEccKeys } from '../asymmetric-crypto';
import { deriveSymmetricCryptoKeyFromContext } from '../derive-key';
import { generateKyberKeys } from '../post-quantum-crypto';
import { hashString } from '../hash';

/**
 * Generates recovery codes
 * @returns The generated recovery codes
 */
export function generateRecoveryCodes(): string {
  return genMnemonic(AES_KEY_BIT_LENGTH);
}

/**
 * Generates encryption keys
 * @returns The generated encryption keys
 */
export async function generateEncryptionKeys(): Promise<EncryptionKeys> {
  try {
    const keyPair = await generateEccKeys();
    const keyPairKyber = await generateKyberKeys();
    const result: EncryptionKeys = {
      userPrivateKey: keyPair.privateKey,
      userPublicKey: keyPair.publicKey,
      userPublicKyberKey: keyPairKyber.publicKey,
      userPrivateKyberKey: keyPairKyber.secretKey,
    };
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to generate encryption keys: ${errorMessage}`));
  }
}
/**
 * Derives a secret key for protecting the recovery keystore
 * @param recoveryCodes - The recovery codes
 * @returns The derived secret key for protecting the idenity keystore
 */
export async function deriveRecoveryKey(recoveryCodes: string): Promise<CryptoKey> {
  const recoveryCodesBuffer = await hashString(AES_KEY_BIT_LENGTH, recoveryCodes);
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_RECOVERY, recoveryCodesBuffer);
}

/**
 * Derives a secret key for protecting the encryption keystore
 * @param baseKey - The base secret key from which a new key secret will be derived
 * @returns The derived secret key for protecting the encryption keystore

*/
export async function deriveEncryptionKeystoreKey(baseKey: Uint8Array): Promise<CryptoKey> {
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_ENC_KEYSTORE, baseKey);
}

/**
 * Generates email encryption keys and encrypts them with a key derived from the base key (stored in session storage)
 *
 * @returns The encrypted idenity keystore
 */
export async function createEncryptionAndRecoveryKeystores(): Promise<{
  encryptionKeystore: EncryptedKeystore;
  recoveryKeystore: EncryptedKeystore;
  recoveryCodes: string;
}> {
  try {
    const userID = getUserID();
    const baseKey = getBaseKey();
    const keys = await generateEncryptionKeys();
    const content = await encryptionKeysToBase64(keys);

    const secretKey = await deriveEncryptionKeystoreKey(baseKey);
    const ciphertext = await createKeystore(secretKey, content, userID, ENCRYPTION_KEYSTORE_TAG);
    const encryptionKeystore: EncryptedKeystore = {
      userID,
      type: KeystoreType.ENCRYPTION,
      encryptedKeys: ciphertext,
    };
    const recoveryCodes = generateRecoveryCodes();
    const recoveryKey = await deriveRecoveryKey(recoveryCodes);
    const encKeys = await createKeystore(recoveryKey, content, userID, RECOVERY_KEYSTORE_TAG);
    const recoveryKeystore: EncryptedKeystore = {
      userID,
      type: KeystoreType.RECOVERY,
      encryptedKeys: encKeys,
    };
    return { encryptionKeystore, recoveryKeystore, recoveryCodes };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to create encryption and recovery keystores: ${errorMessage}`));
  }
}

/**
 * Opens the encrypted keystore containing the encrypiton keys
 *
 * @param encryptedKeystore - The encrypted keystore containing encryption keys
 * @returns The encryption keys
 */
export async function openEncryptionKeystore(encryptedKeystore: EncryptedKeystore): Promise<EncryptionKeys> {
  try {
    if (encryptedKeystore.type != KeystoreType.ENCRYPTION) {
      throw new Error('Input is invalid');
    }
    const baseKey = getBaseKey();
    const secretKey = await deriveEncryptionKeystoreKey(baseKey);
    const json = await openKeystore(
      secretKey,
      encryptedKeystore.encryptedKeys,
      encryptedKeystore.userID,
      ENCRYPTION_KEYSTORE_TAG,
    );
    const keys: EncryptionKeys = await base64ToEncryptionKeys(json);
    return keys;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to open encryption keystore: ${errorMessage}`));
  }
}

/**
 * Opens the recovery keystore and returns the encryption keys
 * @param recoveryCodes - The user's recovery codes
 * @param encryptedKeystore - The encrypted keystore containing encryption keys
 * @returns The encryption keys
 */
export async function openRecoveryKeystore(
  recoveryCodes: string,
  encryptedKeystore: EncryptedKeystore,
): Promise<EncryptionKeys> {
  try {
    if (encryptedKeystore.type != KeystoreType.RECOVERY) {
      throw new Error('Input is invalid');
    }
    const recoveryKey = await deriveRecoveryKey(recoveryCodes);
    const json = await openKeystore(
      recoveryKey,
      encryptedKeystore.encryptedKeys,
      encryptedKeystore.userID,
      RECOVERY_KEYSTORE_TAG,
    );
    const keys: EncryptionKeys = await base64ToEncryptionKeys(json);
    return keys;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to open recovery keystore: ${errorMessage}`));
  }
}
