import { EmailKeys, EncryptedKeystore, KeystoreType } from '../types';
import { emailKeysToBase64, base64ToEmailKeys, genMnemonic } from '../utils';
import { encryptKeystoreContent, decryptKeystoreContent, deriveEncryptionKeystoreKey, deriveRecoveryKey } from './core';
import { generateEmailKeys } from '../email-crypto';

/**
 * Generates email keys and creates encrypted main and recovery keystores
 * The main keystore encryption key is derived from the base key (stored in session storage)
 * The recovery keystore encryption key is derived from the recovery codes
 *
 * @returns The encryption and recovery keystores
 */
export async function createEncryptionAndRecoveryKeystores(
  userEmail: string,
  baseKey: Uint8Array,
): Promise<{
  encryptionKeystore: EncryptedKeystore;
  recoveryKeystore: EncryptedKeystore;
  recoveryCodes: string;
}> {
  try {
    const keys = await generateEmailKeys();
    const content = await emailKeysToBase64(keys);

    const secretKey = await deriveEncryptionKeystoreKey(baseKey);
    const ciphertext = await encryptKeystoreContent(secretKey, content, userEmail, KeystoreType.ENCRYPTION);
    const encryptionKeystore: EncryptedKeystore = {
      userEmail,
      type: KeystoreType.ENCRYPTION,
      encryptedKeys: ciphertext,
    };
    const recoveryCodes = genMnemonic();
    const recoveryKey = await deriveRecoveryKey(recoveryCodes);
    const encKeys = await encryptKeystoreContent(recoveryKey, content, userEmail, KeystoreType.RECOVERY);
    const recoveryKeystore: EncryptedKeystore = {
      userEmail,
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
 * @param baseKey - The base key from which the decryption key will be derived
 * @returns The encryption keys
 */
export async function openEncryptionKeystore(
  encryptedKeystore: EncryptedKeystore,
  baseKey: Uint8Array,
): Promise<EmailKeys> {
  try {
    if (encryptedKeystore.type != KeystoreType.ENCRYPTION) {
      throw new Error('Input is invalid');
    }
    const secretKey = await deriveEncryptionKeystoreKey(baseKey);
    const json = await decryptKeystoreContent(
      secretKey,
      encryptedKeystore.encryptedKeys,
      encryptedKeystore.userEmail,
      KeystoreType.ENCRYPTION,
    );
    const keys: EmailKeys = await base64ToEmailKeys(json);
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
): Promise<EmailKeys> {
  try {
    if (encryptedKeystore.type != KeystoreType.RECOVERY) {
      throw new Error('Input is invalid');
    }
    const recoveryKey = await deriveRecoveryKey(recoveryCodes);
    const json = await decryptKeystoreContent(
      recoveryKey,
      encryptedKeystore.encryptedKeys,
      encryptedKeystore.userEmail,
      KeystoreType.RECOVERY,
    );
    const keys: EmailKeys = await base64ToEmailKeys(json);
    return keys;
  } catch (error) {
    throw new Error('Failed to open recovery keystore', { cause: error });
  }
}
