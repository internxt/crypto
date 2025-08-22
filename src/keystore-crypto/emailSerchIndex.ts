import { EncryptedKeystore, KeystoreType, SearchIndices, uint8ArrayToBase64 } from '../utils';
import { CONTEXT_INDEX, INDEX_KEYSTORE_TAG } from '../constants';
import { createKeystore, openKeystore, getUserID, getBaseKey } from './core';
import { base64ToSearchIndices, searchIndicesToBase64 } from './converters';
import { deriveSymmetricCryptoKeyFromContext } from '../derive-key';

/**
 * Derives a secret key for protecting the index keystore
 * @param baseKey - The base secret key from which a new key secret will be derived
 * @returns The derived secret key for protecting the index keystore
 */
export async function deriveIndexKey(baseKey: Uint8Array): Promise<CryptoKey> {
  return deriveSymmetricCryptoKeyFromContext(CONTEXT_INDEX, baseKey);
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
