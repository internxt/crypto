import axios, { AxiosResponse, AxiosError } from 'axios';
import { KeystoreType, EncryptedKeystore, PublicKeys } from '../types';
import { base64ToEncryptedKeystore, encryptedKeystoreToBase64, base64ToPublicKey } from '../utils';

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
  async sendEncryptedKeystoreToServer(encryptedKeystore: string, url: string): Promise<AxiosResponse> {
    try {
      const response = await axios.post(
        this.baseUrl + `${url}`,
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
  async requestEncryptedKeystore(userID: string, keystoreType: KeystoreType): Promise<string> {
    try {
      const url = `/downloadKeystore/${userID}/${keystoreType}`;
      const response = await axios.get<string>(this.baseUrl + `${url}`, {
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
   * Uploads encrypted keystore to the server
   *
   * @param encryptedKeystore - The encrypted keystore
   * @returns Server response
   */
  async uploadKeystoreToServer(encryptedKeystore: EncryptedKeystore): Promise<AxiosResponse> {
    try {
      const userID = encryptedKeystore.userEmail;
      const keystoreType = encryptedKeystore.type;
      const url = `/uploadKeystore/${userID}/${keystoreType}`;
      const ciphertextBase64 = encryptedKeystoreToBase64(encryptedKeystore);
      const result = await this.sendEncryptedKeystoreToServer(ciphertextBase64, url);
      return result;
    } catch (error) {
      throw new Error('Failed to upload keystore to the server', { cause: error });
    }
  }

  /**
   * Gets a user's encrypted keystore containing encryption keys from the server
   *
   * @returns Encrypted keystore containing encryption keys
   */
  async getEncryptionKeystoreFromServer(userEmail: string): Promise<EncryptedKeystore> {
    return this.getKeystoreFromServer(userEmail, KeystoreType.ENCRYPTION);
  }

  /**
   * Gets a user's encrypted Recovery Keystore from the server
   *
   * @returns Encrypted Recovery Keystore
   */
  async getRecoveryKeystoreFromServer(userEmail: string): Promise<EncryptedKeystore> {
    return this.getKeystoreFromServer(userEmail, KeystoreType.RECOVERY);
  }

  /**
   * Gets a user's encrypted Index Keystore from the server
   *
   * @returns Encrypted Index Keytore
   */
  async getIndexKeystoreFromServer(userEmail: string): Promise<EncryptedKeystore> {
    return this.getKeystoreFromServer(userEmail, KeystoreType.INDEX);
  }

  /**
   * Gets a user's encrypted keystore from the server
   *
   * @param type - The requested keystore's type
   * @returns Encrypted  Keytore
   */
  async getKeystoreFromServer(userEmail: string, type: KeystoreType): Promise<EncryptedKeystore> {
    try {
      const response = await this.requestEncryptedKeystore(userEmail, type);
      const result = base64ToEncryptedKeystore(response);
      return result;
    } catch (error) {
      throw new Error('Failed to retrieve keystore from the server', { cause: error });
    }
  }
  /**
   * Obtains recipients public keys from the server
   *
   * @param emails - The recipients' emails
   * @returns The list of recipients' public keys
   */
  async getRecipientsPublicKeysFromServer(emails: string[]): Promise<string[]> {
    try {
      const response = await axios.get<string[]>('/api/getPublicKeys', {
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
      const publicKeysBase64: string[] = await this.getRecipientsPublicKeysFromServer(emails);
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
