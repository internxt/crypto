import { AxiosResponse } from 'axios';
import { KeystoreType, EncryptedKeystore } from '../utils/types';
import { sendEncryptedKeystoreToServer, requestEncryptedKeystore } from './api';
import { getUserID } from './core';
import { base64ToEncryptedKeystore, encryptedKeystoreToBase64 } from './converters';

/**
 * Uploads encrypted keystore to the server
 * @param encryptedKeystore - The encrypted keystore
 * @param type - The keystore's type
 * @returns Server response
 */
export async function uploadKeystoreToServer(encryptedKeystore: EncryptedKeystore): Promise<AxiosResponse> {
  try {
    const userID = getUserID();
    const keystoreType = encryptedKeystore.type;
    const url = `/uploadKeystore/${userID}/${keystoreType}`;
    const ciphertextBase64 = encryptedKeystoreToBase64(encryptedKeystore);
    const result = await sendEncryptedKeystoreToServer(ciphertextBase64, url);
    return result;
  } catch (error) {
    return Promise.reject(new Error('Could not upload keystore to the server', error));
  }
}

/**
 * Gets a user's encrypted keystore containing encryption keys from the server
 * @returns Encrypted keystore containing encryption keys
 */
export async function getEncryptionKeystoreFromServer(): Promise<EncryptedKeystore> {
  return getKeystoreFromServer(KeystoreType.ENCRYPTION);
}

/**
 * Gets a user's encrypted Identity Keystore from the server
 * @returns Encrypted Identity Keystore
 */
export async function getIdentityKeystoreFromServer(): Promise<EncryptedKeystore> {
  return getKeystoreFromServer(KeystoreType.IDENTITY);
}

/**
 * Gets a user's encrypted Recovery Keystore from the server
 * @returns Encrypted Recovery Keystore
 */
export async function getRecoveryKeystoreFromServer(): Promise<EncryptedKeystore> {
  return getKeystoreFromServer(KeystoreType.RECOVERY);
}

/**
 * Gets a user's encrypted Index Keystore from the server
 * @returns Encrypted Index Keytore
 */
export async function getIndexKeystoreFromServer(): Promise<EncryptedKeystore> {
  return getKeystoreFromServer(KeystoreType.INDEX);
}

/**
 * Gets a user's encrypted keystore from the server
 * @param type - The requested keystore's type
 * @returns Encrypted  Keytore
 */
async function getKeystoreFromServer(type: KeystoreType): Promise<EncryptedKeystore> {
  try {
    const userID = getUserID();
    const keystoreType = type.toString();
    const url = `/downloadKeystore/${userID}/${keystoreType}`;
    const response = await requestEncryptedKeystore(url);
    const result = base64ToEncryptedKeystore(response);
    return result;
  } catch (error) {
    return Promise.reject(new Error('Could not get keystore from the server', error));
  }
}
