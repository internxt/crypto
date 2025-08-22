import axios, { AxiosResponse } from 'axios';
import envService from '../utils/env';

/**
 * Sends a user's encrypted keystore to the server
 * @param keystore - The encrypted keystore
 * @param url - The user's url
 * @returns Server response
 */
export async function sendEncryptedKeystoreToServer(encryptedKeystore: string, url: string): Promise<AxiosResponse> {
  try {
    const baseUrl = envService.getVariable('baseUrl');
    const response = await axios.post(
      baseUrl + `${url}`,
      { encryptedKeystore },
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
        throw new Error('AxiosError:', error);
      }
    }
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to send keystore: ${errorMessage}`);
  }
}

/**
 * Requests a user's encrypted keystore from the server
 * @param url - The user's url
 * @returns The user's encrypted keystore in base64
 */
export async function requestEncryptedKeystore(url: string): Promise<string> {
  try {
    const baseUrl = envService.getVariable('baseUrl');
    const response = await axios.get<string>(baseUrl + `${url}`, {
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
        throw new Error('AxiosError:', error);
      }
    }

    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to retrive keystore: ${errorMessage}`);
  }
}
