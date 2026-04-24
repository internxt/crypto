import { EncryptedKeystore, KeystoreType, HybridKeyPair } from '../types';
import { base64ToUint8Array, genMnemonic } from '../utils';
import {
  encryptKeystoreContent,
  decryptKeystoreContent,
  deriveEncryptionKeystoreKey,
  deriveNewEncryptionKeystoreKey,
  deriveRecoveryKey,
} from './core';
import { genHybridKeys } from '../hybrid-crypto';
import {
  FailedToOpenEncryptionKeyStore,
  FailedToCreateKeyStores,
  FailedToOpenRecoveryKeyStore,
  FailedToChangePasswordForKeyStore,
} from './errors';
import { ARGON2ID_SALT_BYTE_LENGTH } from '../constants';

/**
 * Generates hybrid keys and creates encrypted main and recovery keystores
 * The main keystore encryption key is derived from the user's password
 * The recovery keystore encryption key is derived from the recovery codes
 *
 * @param userEmail - The user's email
 * @param password - The user's password
 * @returns The encryption keys
 *
 * @returns The encryption and recovery keystores, recovery codes and hybrid keys
 */
export async function createEncryptionAndRecoveryKeystores(
  userEmail: string,
  password: string,
): Promise<{
  encryptionKeystore: EncryptedKeystore;
  recoveryKeystore: EncryptedKeystore;
  recoveryCodes: string;
  keys: HybridKeyPair;
}> {
  try {
    const keys = genHybridKeys();

    const { secretKey, salt } = await deriveNewEncryptionKeystoreKey(password);
    const encryptionKeystore = await encryptKeystoreContent(secretKey, keys, userEmail, KeystoreType.ENCRYPTION, salt);

    const recoveryCodes = genMnemonic();
    const recoveryKey = await deriveRecoveryKey(recoveryCodes);
    const recoveryKeystore = await encryptKeystoreContent(recoveryKey, keys, userEmail, KeystoreType.RECOVERY);

    return { encryptionKeystore, recoveryKeystore, recoveryCodes, keys };
  } catch (error) {
    throw new FailedToCreateKeyStores(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Opens the encryption keystore and returns the email encryption keys
 * The decryption key is derived from the user password
 *
 * @param encryptedKeystore - The encrypted keystore containing encryption keys
 * @param password - The user's password
 * @returns The encryption keys
 */
export async function openEncryptionKeystore(
  encryptedKeystore: EncryptedKeystore,
  password: string,
): Promise<HybridKeyPair> {
  try {
    const salt = encryptedKeystore.salt ? base64ToUint8Array(encryptedKeystore.salt) : new Uint8Array();
    if (encryptedKeystore.type !== KeystoreType.ENCRYPTION || salt.length !== ARGON2ID_SALT_BYTE_LENGTH) {
      throw new Error('Input is invalid');
    }
    const secretKey = await deriveEncryptionKeystoreKey(password, salt);
    const keys = await decryptKeystoreContent(secretKey, encryptedKeystore);
    return keys;
  } catch (error) {
    throw new FailedToOpenEncryptionKeyStore(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Opens the recovery keystore and returns the email encryption keys
 * The decryption key is derived from the recovery codes (machine-generated mnemonic)
 *
 * @param recoveryCodes - The user's recovery codes
 * @param encryptedKeystore - The encrypted keystore containing encryption keys
 * @returns The encryption keys
 */
export async function openRecoveryKeystore(
  recoveryCodes: string,
  encryptedKeystore: EncryptedKeystore,
): Promise<HybridKeyPair> {
  try {
    if (encryptedKeystore.type !== KeystoreType.RECOVERY) {
      throw new Error('Input is invalid');
    }
    const recoveryKey = await deriveRecoveryKey(recoveryCodes);
    const keys = await decryptKeystoreContent(recoveryKey, encryptedKeystore);
    return keys;
  } catch (error) {
    throw new FailedToOpenRecoveryKeyStore(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Re-encrypts the encryption keystore with a new password
 * The decryption key is derived from the user password
 *
 * @param encryptedKeystore - The encrypted keystore containing encryption keys
 * @param oldPassword - The user's old password
 * @param newPassword - The user's new password
 * @returns The keys and new re-encrypted keystore
 */
export async function changePasswordForEncryptionKeystore(
  encryptedKeystore: EncryptedKeystore,
  oldPassword: string,
  newPassword: string,
): Promise<{ keys: HybridKeyPair; newKeystore: EncryptedKeystore }> {
  try {
    const keys = await openEncryptionKeystore(encryptedKeystore, oldPassword);

    const { secretKey, salt } = await deriveNewEncryptionKeystoreKey(newPassword);
    const newKeystore = await encryptKeystoreContent(
      secretKey,
      keys,
      encryptedKeystore.userEmail,
      KeystoreType.ENCRYPTION,
      salt,
    );

    return { newKeystore, keys };
  } catch (error) {
    throw new FailedToChangePasswordForKeyStore(error instanceof Error ? error.message : String(error));
  }
}
