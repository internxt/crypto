import axios, { AxiosResponse, AxiosError } from 'axios';
import { KeystoreType, EncryptedKeystore, PublicKeys, PublicKeysBase64 } from '../types';
import { base64ToPublicKey } from '../utils';

export class KeyServiceAPI {
  private readonly baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  /**
   * Converts the specific client error into a proprietary error for our apps
   * @param error
   * @private
   */
  private normalizeError(error: AxiosError) {
    let errorMessage: string;
    if (error.response?.status === 401) {
      errorMessage = 'Unauthorized: Invalid or expired token';
    } else if (error.response?.status === 403) {
      errorMessage = 'Forbidden: Insufficient permissions';
    } else if (error.response?.status === 404) {
      errorMessage = 'Keystore not found for the specified user';
    } else {
      errorMessage = 'AxiosError:' + (error.message ?? 'Unknown error');
    }

    throw new Error(errorMessage);
  }

  /**
   * Sends a user's encrypted keystore to the server
   * @param keystore - The encrypted keystore
   * @param url - The user specific part of the url
   * @returns Server response
   */
  async uploadKeystoreToServer(encryptedKeystore: EncryptedKeystore): Promise<AxiosResponse> {
    try {
      const url = `${this.baseUrl}/uploadKeystore`;
      const response = await axios.post(
        url,
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
        this.normalizeError(error);
      }
      throw new Error('Failed to send keystore', { cause: error });
    }
  }

  /**
   * Requests a user's encrypted keystore from the server
   * @param url - The user-specific part of the url
   * @returns The user's encrypted keystore as base64 string
   */
  async getKeystoreFromServer(userID: string, keystoreType: KeystoreType): Promise<EncryptedKeystore> {
    try {
      const url = `${this.baseUrl}/downloadKeystore`;
      const response = await axios.get<EncryptedKeystore>(url, {
        params: { userID, keystoreType },
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json',
        },
      });
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        this.normalizeError(error);
      }

      throw new Error('Failed to retrive keystore', { cause: error });
    }
  }

  /**
   * Obtains recipients public keys from the server
   *
   * @param emails - The recipients' emails
   * @returns The list of recipients' public keys
   */
  async getRecipientsPublicKeysFromServer(emails: string[]): Promise<PublicKeysBase64[]> {
    try {
      const url = `${this.baseUrl}/getPublicKeys`;
      const response = await axios.get<PublicKeysBase64[]>(url, {
        params: {
          emails: emails,
        },
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json',
        },
      });
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        this.normalizeError(error);
      }
      throw new Error('Failed to retrieve public keys', { cause: error });
    }
  }

  /**
   * Obtains the recipient public keys from the server
   *
   * @param email - The recipients' emails
   * @returns The list of recipients' public keys
   */
  async getRecipientsPublicKeys(emails: string[]): Promise<PublicKeys[]> {
    try {
      const publicKeysBase64: PublicKeysBase64[] = await this.getRecipientsPublicKeysFromServer(emails);
      const result: PublicKeys[] = [];
      for (const keyBase64 of publicKeysBase64) {
        const publicKeys = await base64ToPublicKey(keyBase64);
        result.push(publicKeys);
      }
      return result;
    } catch (error) {
      throw new Error('Failed to get recipients public keys', { cause: error });
    }
  }
}

export function getKeyServiceAPI(baseUrl: string): KeyServiceAPI {
  return new KeyServiceAPI(baseUrl);
}
