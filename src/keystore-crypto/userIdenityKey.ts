import { IdentityKeys, EncryptedKeystore, KeystoreType, IDENTITY_KEYSTORE_TAG, CONTEXT_LOGIN } from '../utils';
import { createKeystore, openKeystore, getUserID, getBaseKey } from './core';
import { base64ToIdentityKeys, identityKeysToBase64 } from './converters';
import { generateEccKeys } from '../asymmetric-crypto';
import { deriveSymmetricCryptoKeyFromContext } from '../derive-key';

/**
 * Derives a secret key for protecting the idenity keystore
 * @param baseKey - The base secret key from which a new key secret will be derived
 * @returns The derived secret key for protecting the idenity keystore
 */
export async function deriveIdentityKeystoreKey(baseKey: Uint8Array): Promise<CryptoKey> {
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_LOGIN, baseKey);
}

/**
 * Generates idenity keys
 * @returns The generated identity keys
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
