import { IdentityKeys, EncryptionKeys, EncryptedKeystore } from '../utils/types';
import { IDENTITY_KEYSTORE_TAG, ENCRYPTION_KEYSTORE_TAG, RECOVERY_KEYSTORE_TAG } from '../utils/constants';
import { createKeystore, openKeystore } from './utils';

export async function createIdentityKeystore(
  secretKey: CryptoKey,
  nonce: number,
  keys: IdentityKeys,
  userID: string,
): Promise<EncryptedKeystore> {
  try {
    const content = JSON.stringify(keys);
    const result = await createKeystore(secretKey, nonce, content, userID, IDENTITY_KEYSTORE_TAG);
    return result;
  } catch (error) {
    return Promise.reject(new Error(`Identity keystore creation failed: ${error}`));
  }
}

export async function openIdentityKeystore(
  secretKey: CryptoKey,
  encryptedKeystore: EncryptedKeystore,
  userID: string,
): Promise<IdentityKeys> {
  try {
    const json = await openKeystore(
      secretKey,
      encryptedKeystore.iv,
      encryptedKeystore.encryptedKeys,
      userID,
      IDENTITY_KEYSTORE_TAG,
    );
    const keys: IdentityKeys = JSON.parse(json);
    return keys;
  } catch (error) {
    return Promise.reject(new Error(`Opening identity keystore failed: ${error}`));
  }
}

export async function createEncryptionKeystore(
  secretKey: CryptoKey,
  nonce: number,
  keys: EncryptionKeys,
  userID: string,
): Promise<EncryptedKeystore> {
  try {
    const content = JSON.stringify(keys);
    const result = await createKeystore(secretKey, nonce, content, userID, ENCRYPTION_KEYSTORE_TAG);
    return result;
  } catch (error) {
    return Promise.reject(new Error(`Encryption keystore creation failed: ${error}`));
  }
}

export async function openEncryptionKeystore(
  secretKey: CryptoKey,
  encryptedKeystore: EncryptedKeystore,
  userID: string,
): Promise<EncryptionKeys> {
  try {
    const json = await openKeystore(
      secretKey,
      encryptedKeystore.iv,
      encryptedKeystore.encryptedKeys,
      userID,
      ENCRYPTION_KEYSTORE_TAG,
    );
    const keys: EncryptionKeys = JSON.parse(json);
    return keys;
  } catch (error) {
    return Promise.reject(new Error(`Opening encryption keystore failed: ${error}`));
  }
}

export async function createRecoveryKeystore(
  recoveryKey: CryptoKey,
  nonce: number,
  keys: EncryptionKeys,
  userID: string,
): Promise<EncryptedKeystore> {
  try {
    const content = JSON.stringify(keys);
    const result = await createKeystore(recoveryKey, nonce, content, userID, RECOVERY_KEYSTORE_TAG);
    return result;
  } catch (error) {
    return Promise.reject(new Error(`Encryption keystore creation failed: ${error}`));
  }
}

export async function openRecoveryKeystore(
  recoveryKey: CryptoKey,
  encryptedKeystore: EncryptedKeystore,
  userID: string,
): Promise<EncryptionKeys> {
  try {
    const json = await openKeystore(
      recoveryKey,
      encryptedKeystore.iv,
      encryptedKeystore.encryptedKeys,
      userID,
      RECOVERY_KEYSTORE_TAG,
    );
    const keys: EncryptionKeys = JSON.parse(json);
    return keys;
  } catch (error) {
    return Promise.reject(new Error(`Opening recovery keystore failed: ${error}`));
  }
}
