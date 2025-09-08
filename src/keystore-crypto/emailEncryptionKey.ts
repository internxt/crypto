import { EncryptionKeys, EncryptedKeystore, KeystoreType } from '../types';
import { encryptionKeysToBase64, base64ToEncryptionKeys, genMnemonic } from '../utils';
import { ENCRYPTION_KEYSTORE_TAG, RECOVERY_KEYSTORE_TAG, AES_KEY_BIT_LENGTH } from '../constants';
import {
  encryptKeystoreContent,
  decryptKeystoreContent,
  getUserID,
  getBaseKey,
  deriveEncryptionKeystoreKey,
  deriveRecoveryKey,
} from './core';
import { generateEccKeys } from '../asymmetric-crypto';
import { generateKyberKeys } from '../post-quantum-crypto';

/**
 * Generates recovery codes
 *
 * @returns The generated recovery codes
 */
export function generateRecoveryCodes(): string {
  return genMnemonic(AES_KEY_BIT_LENGTH);
}

/**
 * Generates encryption keys
 *
 * @returns The generated encryption keys
 */
export async function generateEncryptionKeys(): Promise<EncryptionKeys> {
  try {
    const keyPair = await generateEccKeys();
    const keyPairKyber = generateKyberKeys();
    const result: EncryptionKeys = {
      userPrivateKey: keyPair.privateKey,
      userPublicKey: keyPair.publicKey,
      userPublicKyberKey: keyPairKyber.publicKey,
      userPrivateKyberKey: keyPairKyber.secretKey,
    };
    return result;
  } catch (error) {
    throw new Error('Failed to generate encryption keys', { cause: error });
  }
}

/**
 * Generates email encryption keys and creates encrypted encryption and recovery keystores
 * The encryption key is derived from the base key (stored in session storage)
 *
 * @returns The encryption and recovery keystores
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
    const ciphertext = await encryptKeystoreContent(secretKey, content, userID, ENCRYPTION_KEYSTORE_TAG);
    const encryptionKeystore: EncryptedKeystore = {
      userID,
      type: KeystoreType.ENCRYPTION,
      encryptedKeys: ciphertext,
    };
    const recoveryCodes = generateRecoveryCodes();
    const recoveryKey = await deriveRecoveryKey(recoveryCodes);
    const encKeys = await encryptKeystoreContent(recoveryKey, content, userID, RECOVERY_KEYSTORE_TAG);
    const recoveryKeystore: EncryptedKeystore = {
      userID,
      type: KeystoreType.RECOVERY,
      encryptedKeys: encKeys,
    };
    return { encryptionKeystore, recoveryKeystore, recoveryCodes };
  } catch (error) {
    throw new Error('Failed to create encryption and recovery keystores', { cause: error });
  }
}

/**
 * Opens the encryption keystore and returns the email encryption keys
 * The decryption key is derived from the base key (stored in session storage)
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
    const json = await decryptKeystoreContent(
      secretKey,
      encryptedKeystore.encryptedKeys,
      encryptedKeystore.userID,
      ENCRYPTION_KEYSTORE_TAG,
    );
    const keys: EncryptionKeys = await base64ToEncryptionKeys(json);
    return keys;
  } catch (error) {
    throw new Error('Failed to open encryption keystore', { cause: error });
  }
}

/**
 * Opens the recovery keystore and returns the email encryption keys
 * The decryption key is derived from the base key (stored in session storage)
 *
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
    const json = await decryptKeystoreContent(
      recoveryKey,
      encryptedKeystore.encryptedKeys,
      encryptedKeystore.userID,
      RECOVERY_KEYSTORE_TAG,
    );
    const keys: EncryptionKeys = await base64ToEncryptionKeys(json);
    return keys;
  } catch (error) {
    throw new Error('Failed to open recovery keystore', { cause: error });
  }
}
