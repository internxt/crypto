import axios from 'axios';
import { PublicKeysBase64, PublicKeys } from '../utils';
import { base64ToPublicKey } from './converters';

/**
 * Requests recipients public keys from the server
 * @param emails - The emails of recipients
 * @param token - The senders's bearer token
 * @returns The user's public keys
 */
export async function getRecipientsPublicKeysHex(emails: string[], token: string): Promise<PublicKeysBase64[]> {
  try {
    const response = await axios.get<PublicKeysBase64[]>('/api/getPublicKeys', {
      params: {
        emails: emails,
      },
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
        throw new Error('User is not found');
      } else {
        throw new Error('AxiosError: Error retrieving public keys', error);
      }
    }
    console.error('Error retrieving public keys:', error);
    throw error;
  }
}

export async function getRecipientsPublicKeys(emails: string[], token: string): Promise<PublicKeys[]> {
  try {
    const publicKeysHex: PublicKeysBase64[] = await getRecipientsPublicKeysHex(emails, token);
    const result: PublicKeys[] = [];
    for (const keyHex of publicKeysHex) {
      const publicKeys = await base64ToPublicKey(keyHex);
      result.push(publicKeys);
    }
    return result;
  } catch (error) {
    return Promise.reject(new Error('Could not get recipients public keys', error));
  }
}
