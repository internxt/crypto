import { EncryptedKeystore, KeystoreType, SearchIndices, uint8ArrayToBase64 } from '../utils';
import { INDEX_KEYSTORE_TAG } from '../constants';
import { encryptKeystoreContent, decryptKeystoreContent, getUserID, getBaseKey, deriveIndexKey } from './core';
import { base64ToSearchIndices, searchIndicesToBase64 } from './converters';

/**
 * Creates an encrypted keystore for search indices
 * The encryption key is derived from the base key (stored in session storage)
 *
 * @param indices - The email search indices
 * @returns The encrypted keystore containing search indices
 */
export async function encryptCurrentSearchIndices(indices: SearchIndices): Promise<EncryptedKeystore> {
  try {
    const userID = getUserID();
    const baseKey = getBaseKey();

    console.log('HOLA: ', userID, uint8ArrayToBase64(baseKey));
    const indexKey = await deriveIndexKey(baseKey);
    const content = searchIndicesToBase64(indices);
    const encKeys = await encryptKeystoreContent(indexKey, content, userID, INDEX_KEYSTORE_TAG);
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

/**
 * Opens an encrypted keystore with search indices
 * The decryption key is derived from the base key (stored in session storage)
 *
 * @param encryptedKeystore - The encrypted keystore containing search indices
 * @returns The email search indices
 */
export async function decryptCurrentSearchIndices(encryptedKeystore: EncryptedKeystore): Promise<SearchIndices> {
  try {
    if (encryptedKeystore.type != KeystoreType.INDEX) {
      throw new Error('Input is invalid');
    }
    const baseKey = getBaseKey();
    const indexKey = await deriveIndexKey(baseKey);
    const json = await decryptKeystoreContent(
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
