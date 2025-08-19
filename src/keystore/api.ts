import axios, { AxiosResponse } from 'axios';
import { KeystoreType } from '../utils/types';
import sessionStorageService from '../utils/sessionStorageService';
import envService from '../utils/env';
/**
 * Sends a user's keystore to the server
 * @param encryptedKeystore - The encrypted keystore
 * @param type - The keystore's type
 * @returns Server response
 */
export async function sendKeystore(encryptedKeystore: Uint8Array, type: KeystoreType): Promise<AxiosResponse> {
  try {
    const userID = sessionStorageService.get('userID');
    const baseUrl = envService.getVariable('baseUrl');
    const response = await axios.post(
      baseUrl + '/uploadKeystore',
      { encryptedKeystore, userID, type },
      {
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json',
        },
      },
    );
    return response;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      if (error.response?.status === 401) {
        throw new Error('Unauthorized: Invalid or expired token');
      }
      if (error.response?.status === 403) {
        throw new Error('Forbidden: Insufficient permissions');
      } else {
        throw new Error('AxiosError: Error sending keystore', error);
      }
    }
    console.error('Error sending keystore:', error);
    throw error;
  }
}

/**
 * Requests a user's keystore from the server
 * @param type - The requested keystore's type
 * @returns The user's keystore
 */
export async function getKeystoreFromServer(type: KeystoreType): Promise<Uint8Array> {
  try {
    const userID = sessionStorageService.get('userID');
    const baseUrl = envService.getVariable('baseUrl');
    const response = await axios.get<Uint8Array>(baseUrl + `/downloadKeystore/${userID}/${type}`, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
      },
    });
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      if (error.response?.status === 401) {
        throw new Error('Unauthorized: Invalid or expired token');
      }
      if (error.response?.status === 403) {
        throw new Error('Forbidden: Insufficient permissions');
      }
      if (error.response?.status === 404) {
        throw new Error('Keystore not found for the specified user');
      } else {
        throw new Error('AxiosError: Error retrieving keystore', error);
      }
    }
    console.error('Error retrieving keystore:', error);
    throw error;
  }
}
