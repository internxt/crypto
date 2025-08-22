import { IdentityKeys, EncryptedKeystore, KeystoreType } from '../utils';
import { IDENTITY_KEYSTORE_TAG } from '../constants';
import {
  encryptKeystoreContent,
  decryptKeystoreContent,
  getUserID,
  getBaseKey,
  deriveIdentityKeystoreKey,
} from './core';
import { base64ToIdentityKeys, identityKeysToBase64 } from './converters';
import { generateEccKeys } from '../asymmetric-crypto';

/**
 * Generates user idenity keys
 *
 * @returns The user identity keys
 */
export async function generateIdentityKeys(): Promise<IdentityKeys> {
  try {
    const keyPair = await generateEccKeys();
    const result: IdentityKeys = {
      userPrivateKey: keyPair.privateKey,
      userPublicKey: keyPair.publicKey,
    };
    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return Promise.reject(new Error(`Failed to generate idenity keys: ${errorMessage}`));
  }
}

/**
 * Generates user identity keys and creates an encrypted identity keystore
 * The encryption key is derived from the base key (stored in session storage)
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
    const encryptedKeys = await encryptKeystoreContent(secretKey, content, userID, IDENTITY_KEYSTORE_TAG);
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
 * The decryption key is derived from the base key (stored in session storage)
 *
 * @param encryptedKeystore - The encrypted identity keystore
 * @returns The identity keys
 */
export async function openIdentityKeystore(encryptedKeystore: EncryptedKeystore): Promise<IdentityKeys> {
  try {
    if (encryptedKeystore.type != KeystoreType.IDENTITY) {
      throw new Error('Input is invalid');
    }
    const baseKey = getBaseKey();
    const secretKey = await deriveIdentityKeystoreKey(baseKey);
    const json = await decryptKeystoreContent(
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
