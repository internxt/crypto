import { IdentityKeys, EncryptedKeystore, KEYSTORE_TAGS } from '../types';
import {
  encryptKeystoreContent,
  decryptKeystoreContent,
  getUserID,
  getBaseKey,
  deriveIdentityKeystoreKey,
} from './core';
import { base64ToIdentityKeys, identityKeysToBase64 } from '../utils';
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
    throw new Error('Failed to generate idenity keys', { cause: error });
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
    const type = KEYSTORE_TAGS.IDENTITY;
    const userEmail = getUserID();
    const baseKey = getBaseKey();
    const keys = await generateIdentityKeys();
    const content = await identityKeysToBase64(keys);
    const secretKey = await deriveIdentityKeystoreKey(baseKey);
    const encryptedKeys = await encryptKeystoreContent(secretKey, content, userEmail, KEYSTORE_TAGS.IDENTITY);
    const result: EncryptedKeystore = {
      userEmail,
      type,
      encryptedKeys,
    };
    return result;
  } catch (error) {
    throw new Error('Failed to create identity keystore', { cause: error });
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
    if (encryptedKeystore.type != KEYSTORE_TAGS.IDENTITY) {
      throw new Error('Input is invalid');
    }
    const baseKey = getBaseKey();
    const secretKey = await deriveIdentityKeystoreKey(baseKey);
    const json = await decryptKeystoreContent(
      secretKey,
      encryptedKeystore.encryptedKeys,
      encryptedKeystore.userEmail,
      KEYSTORE_TAGS.IDENTITY,
    );
    const keys: IdentityKeys = await base64ToIdentityKeys(json);
    return keys;
  } catch (error) {
    throw new Error('Failed to open identity keystore', { cause: error });
  }
}
