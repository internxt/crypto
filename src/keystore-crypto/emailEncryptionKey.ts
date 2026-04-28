import { EncryptedKeystore, KeystoreType, HybridKeyPair } from '../types';
import { genMnemonic } from '../utils';
import {
  encryptKeystoreContent,
  decryptKeystoreContent,
  deriveEncryptionKeystoreKeyFromMnemonic,
  deriveRecoveryKey,
} from './core';
import { genHybridKeys } from '../hybrid-crypto';
import {
  FailedToOpenEncryptionKeyStore,
  FailedToCreateKeyStores,
  FailedToOpenRecoveryKeyStore,
  FailedToChangeMnemonicForKeyStore,
  InvalidInputKeyStore,
} from './errors';

/**
 * Generates hybrid keys and creates encrypted main and recovery keystores
 * The main keystore encryption key is derived from the user's mnemonic
 * The recovery keystore encryption key is derived from the recovery codes
 *
 * @param userEmail - The user's email
 * @param mnemonic - The user's mnemonic
 * @returns The encryption keys
 *
 * @returns The encryption and recovery keystores, recovery codes and hybrid keys
 */
export async function createEncryptionAndRecoveryKeystores(
  userEmail: string,
  mnemonic: string,
): Promise<{
  encryptionKeystore: EncryptedKeystore;
  recoveryKeystore: EncryptedKeystore;
  recoveryCodes: string;
  keys: HybridKeyPair;
}> {
  try {
    const keys = genHybridKeys();

    const secretKey = await deriveEncryptionKeystoreKeyFromMnemonic(mnemonic);
    const encryptionKeystore = await encryptKeystoreContent(secretKey, keys, userEmail, KeystoreType.ENCRYPTION);

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
 * The decryption key is derived from the user mnemonic
 *
 * @param encryptedKeystore - The encrypted keystore containing encryption keys
 * @param mnemonic - The user's mnemonic
 * @returns The encryption keys
 */
export async function openEncryptionKeystore(
  encryptedKeystore: EncryptedKeystore,
  mnemonic: string,
): Promise<HybridKeyPair> {
  try {
    if (encryptedKeystore.type !== KeystoreType.ENCRYPTION) {
      throw new InvalidInputKeyStore();
    }
    const secretKey = await deriveEncryptionKeystoreKeyFromMnemonic(mnemonic);
    const keys = await decryptKeystoreContent(secretKey, encryptedKeystore);
    return keys;
  } catch (error) {
    if (error instanceof InvalidInputKeyStore) throw error;
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
      throw new InvalidInputKeyStore();
    }
    const recoveryKey = await deriveRecoveryKey(recoveryCodes);
    const keys = await decryptKeystoreContent(recoveryKey, encryptedKeystore);
    return keys;
  } catch (error) {
    if (error instanceof InvalidInputKeyStore) throw error;
    throw new FailedToOpenRecoveryKeyStore(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Re-encrypts the encryption keystore with a new mnemonic
 * The decryption key is derived from the user mnemonic
 *
 * @param encryptedKeystore - The encrypted keystore containing encryption keys
 * @param oldMnemonic - The user's old mnemonic
 * @param newMnemonic - The user's new mnemonic
 * @returns The keys and new re-encrypted keystore
 */
export async function changeMnemonicForEncryptionKeystore(
  encryptedKeystore: EncryptedKeystore,
  oldMnemonic: string,
  newMnemonic: string,
): Promise<{ keys: HybridKeyPair; newKeystore: EncryptedKeystore }> {
  try {
    const keys = await openEncryptionKeystore(encryptedKeystore, oldMnemonic);

    const secretKey = await deriveEncryptionKeystoreKeyFromMnemonic(newMnemonic);
    const newKeystore = await encryptKeystoreContent(
      secretKey,
      keys,
      encryptedKeystore.userEmail,
      KeystoreType.ENCRYPTION,
    );

    return { newKeystore, keys };
  } catch (error) {
    if (error instanceof InvalidInputKeyStore) throw error;
    throw new FailedToChangeMnemonicForKeyStore(error instanceof Error ? error.message : String(error));
  }
}
