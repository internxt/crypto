import axios, { AxiosResponse } from 'axios';
import { KeystoreType } from '../utils/types';

/**
 * Sends a user's keystore to the server
 * @param encryptedKeystore - The encrypted keystore
 * @param userID - The user's ID
 * @param token - The user's bearer token
 * @returns Server response
 */
export async function sendKeystore(
  encryptedKeystore: Uint8Array,
  userID: string,
  token: string,
  type: KeystoreType,
): Promise<AxiosResponse> {
  try {
    const response = await axios.post(
      `/api/keystore/${type}`,
      { encryptedKeystore, userID, type },
      {
        headers: {
          Authorization: `Bearer ${token}`,
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
 * @param userID - The user's ID
 * @param token - The user's bearer token
 * @returns The user's keystore
 */
export async function getKeystore(userID: string, token: string, type: KeystoreType): Promise<Uint8Array> {
  try {
    const response = await axios.get<Uint8Array>(`/api/keystore/${userID}/${type}`, {
      headers: {
        Authorization: `Bearer ${token}`,
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
