import { EncryptedKeystore, KeystoreType, HybridKeyPair } from '../types';
import { genMnemonic } from '../utils';
import {
  encryptKeystoreContent,
  decryptKeystoreContent,
  deriveEncryptionKeystoreKey,
  deriveNewEncryptionKeystoreKey,
  deriveRecoveryKey,
} from './core';
import { genHybridKeys } from '../hybrid-crypto';

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
  salt: Uint8Array;
}> {
  try {
    const keys = genHybridKeys();

    const { secretKey, salt } = await deriveNewEncryptionKeystoreKey(password);
    const encryptionKeystore = await encryptKeystoreContent(secretKey, keys, userEmail, KeystoreType.ENCRYPTION);

    const recoveryCodes = genMnemonic();
    const recoveryKey = await deriveRecoveryKey(recoveryCodes);
    const recoveryKeystore = await encryptKeystoreContent(recoveryKey, keys, userEmail, KeystoreType.RECOVERY);

    return { encryptionKeystore, recoveryKeystore, recoveryCodes, keys, salt };
  } catch (error) {
    throw new Error('Failed to create encryption and recovery keystores', { cause: error });
  }
}

/**
 * Opens the encryption keystore and returns the email encryption keys
 * The decryption key is derived from the user password
 *
 * @param encryptedKeystore - The encrypted keystore containing encryption keys
 * @param password - The user's password
 * @param salt - The keystore's salt
 * @returns The encryption keys
 */
export async function openEncryptionKeystore(
  encryptedKeystore: EncryptedKeystore,
  password: string,
  salt: Uint8Array,
): Promise<HybridKeyPair> {
  try {
    if (encryptedKeystore.type != KeystoreType.ENCRYPTION) {
      throw new Error('Input is invalid');
    }
    const secretKey = await deriveEncryptionKeystoreKey(password, salt);
    const keys = await decryptKeystoreContent(secretKey, encryptedKeystore);
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
): Promise<HybridKeyPair> {
  try {
    if (encryptedKeystore.type != KeystoreType.RECOVERY) {
      throw new Error('Input is invalid');
    }
    const recoveryKey = await deriveRecoveryKey(recoveryCodes);
    const keys = await decryptKeystoreContent(recoveryKey, encryptedKeystore);
    return keys;
  } catch (error) {
    throw new Error('Failed to open recovery keystore', { cause: error });
  }
}
