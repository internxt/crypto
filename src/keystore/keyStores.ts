import {
  IdentityKeys,
  EncryptionKeys,
  EncryptedKeystore,
  KeystoreType,
  IDENTITY_KEYSTORE_TAG,
  ENCRYPTION_KEYSTORE_TAG,
  RECOVERY_KEYSTORE_TAG,
} from '../utils';
import { createKeystore, openKeystore, getUserID, getBaseKey } from './utils';
import {
  deriveIdentityKeystoreKey,
  deriveEncryptionKeystoreKey,
  generateIdentityKeys,
  generateEncryptionKeys,
  generateRecoveryCodes,
  deriveRecoveryKey,
} from './keys';
import {
  base64ToEncryptionKeys,
  base64ToIdentityKeys,
  encryptionKeysToBase64,
  identityKeysToBase64,
} from './converters';

/**
 * Generates idenity keys and encrypts them with a key derived from the base key (stored in session storage)
 * @returns The encrypted idenity keystore
 */
export async function createIdentityKeystore(): Promise<EncryptedKeystore> {
  try {
    const type = KeystoreType.IDENTITY;
    const userID = getUserID();
    const baseKey = getBaseKey();
    const keys = await generateIdentityKeys();
    const content = await identityKeysToBase64(keys);
    const secretKey = await deriveIdentityKeystoreKey(baseKey);
    const encryptedKeys = await createKeystore(secretKey, 0, content, userID, IDENTITY_KEYSTORE_TAG);
    const result: EncryptedKeystore = {
      userID,
      type,
      encryptedKeys,
    };
    return result;
  } catch (error) {
    return Promise.reject(new Error(`Identity keystore creation failed: ${error}`));
  }
}

/**
 * Opens the encrypted identity keystore
 * @param recoveryCodes - The encrypted identity keystore
 * @returns The identity keys
 */
export async function openIdentityKeystore(encryptedKeystore: EncryptedKeystore): Promise<IdentityKeys> {
  try {
    if (encryptedKeystore.type != KeystoreType.IDENTITY) {
      throw new Error('Input is invalid');
    }
    const baseKey = getBaseKey();
    const secretKey = await deriveIdentityKeystoreKey(baseKey);
    const json = await openKeystore(
      secretKey,
      encryptedKeystore.encryptedKeys,
      encryptedKeystore.userID,
      IDENTITY_KEYSTORE_TAG,
    );
    const keys: IdentityKeys = await base64ToIdentityKeys(json);
    return keys;
  } catch (error) {
    return Promise.reject(new Error(`Opening identity keystore failed: ${error}`));
  }
}

/**
 * Generates idenity keys and encrypts them with a key derived from the base key (stored in session storage)
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
    const ciphertext = await createKeystore(secretKey, 0, content, userID, ENCRYPTION_KEYSTORE_TAG);
    const encryptionKeystore: EncryptedKeystore = {
      userID,
      type: KeystoreType.ENCRYPTION,
      encryptedKeys: ciphertext,
    };
    const recoveryCodes = generateRecoveryCodes();
    const recoveryKey = await deriveRecoveryKey(recoveryCodes);
    const encKeys = await createKeystore(recoveryKey, 0, content, userID, RECOVERY_KEYSTORE_TAG);
    const recoveryKeystore: EncryptedKeystore = {
      userID,
      type: KeystoreType.RECOVERY,
      encryptedKeys: encKeys,
    };
    return { encryptionKeystore, recoveryKeystore, recoveryCodes };
  } catch (error) {
    return Promise.reject(new Error(`Encryption and recovery keystores creation failed: ${error}`));
  }
}

/**
 * Opens the encrypted keystore containing the encrypiton keys
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
    return Promise.reject(new Error(`Opening encryption keystore failed: ${error}`));
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
    return Promise.reject(new Error(`Opening recovery keystore failed: ${error}`));
  }
}
