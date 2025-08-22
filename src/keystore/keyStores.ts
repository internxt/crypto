import {
  IdentityKeys,
  EncryptionKeys,
  EncryptedKeystore,
  KeystoreType,
  SearchIndices,
  IDENTITY_KEYSTORE_TAG,
  ENCRYPTION_KEYSTORE_TAG,
  RECOVERY_KEYSTORE_TAG,
  INDEX_KEYSTORE_TAG,
  uint8ArrayToBase64,
} from '../utils';
import { createKeystore, openKeystore, getUserID, getBaseKey } from './core';
import {
  deriveIdentityKeystoreKey,
  deriveEncryptionKeystoreKey,
  generateIdentityKeys,
  generateEncryptionKeys,
  generateRecoveryCodes,
  deriveRecoveryKey,
  deriveIndexKey,
} from './keys';
import {
  base64ToEncryptionKeys,
  base64ToIdentityKeys,
  base64ToSearchIndices,
  encryptionKeysToBase64,
  identityKeysToBase64,
  searchIndicesToBase64,
} from './converters';

/**
 * Generates idenity keys and encrypts them with a key derived from the base key (stored in session storage)
 *
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
    const encryptedKeys = await createKeystore(secretKey, content, userID, IDENTITY_KEYSTORE_TAG);
    const result: EncryptedKeystore = {
      userID,
      type,
      encryptedKeys,
    };
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to create identity keystore: ${errorMessage}`));
  }
}

/**
 * Opens the encrypted identity keystore
 *
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
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to open identity keystore: ${errorMessage}`));
  }
}

/**
 * Generates idenity keys and encrypts them with a key derived from the base key (stored in session storage)
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
    console.log('HOLA: ENC ', userID, uint8ArrayToBase64(baseKey));
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

export async function encryptCurrentSearchIndices(indices: SearchIndices): Promise<EncryptedKeystore> {
  try {
    const userID = getUserID();
    const baseKey = getBaseKey();

    console.log('HOLA: ', userID, uint8ArrayToBase64(baseKey));
    const indexKey = await deriveIndexKey(baseKey);
    const content = searchIndicesToBase64(indices);
    const encKeys = await createKeystore(indexKey, content, userID, INDEX_KEYSTORE_TAG);
    const indexKeystrore: EncryptedKeystore = {
      userID,
      type: KeystoreType.INDEX,
      encryptedKeys: encKeys,
    };
    return indexKeystrore;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to encrypt search indices: ${errorMessage}`);
  }
}

export async function decryptCurrentSearchIndices(encryptedKeystore: EncryptedKeystore): Promise<SearchIndices> {
  try {
    if (encryptedKeystore.type != KeystoreType.INDEX) {
      throw new Error('Input is invalid');
    }
    const baseKey = getBaseKey();
    const indexKey = await deriveIndexKey(baseKey);
    const json = await openKeystore(
      indexKey,
      encryptedKeystore.encryptedKeys,
      encryptedKeystore.userID,
      INDEX_KEYSTORE_TAG,
    );
    const indices: SearchIndices = await base64ToSearchIndices(json);
    return indices;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to decrypt search index: ${errorMessage}`);
  }
}
