import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { KeystoreType, EncryptedKeystore } from '../../src/types';
import { getKeyServiceAPI } from '../../src/keystore-service';
import sessionStorageService from '../../src/storage-service/sessionStorageService';
import { encryptedKeystoreToBase64 } from '../../src/utils';

vi.mock('axios');

describe('Test keystore send/get functions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const mockUserID = 'userID';
  const mockType = KeystoreType.ENCRYPTION;
  const mockCiphertext = { iv: new Uint8Array([1, 2, 3, 4, 5]), ciphertext: new Uint8Array([1, 2, 3, 4, 5]) };
  const mockEncryptedKeystore: EncryptedKeystore = {
    userID: mockUserID,
    encryptedKeys: mockCiphertext,
    type: mockType,
  };
  const mockEncryptedKeystoreBase64 = encryptedKeystoreToBase64(mockEncryptedKeystore);
  const service = getKeyServiceAPI('test-base-url');

  describe('sendKeystore', () => {
    const url = `/uploadKeystore/${mockUserID}`;

    it('should successfully send keystore with valid parameters', async () => {
      const mockResponse = {
        data: { success: true, message: 'Keystore uploaded successfully' },
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {},
      };

      vi.mocked(axios.post).mockResolvedValue(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      const result = await service.sendEncryptedKeystoreToServer(mockEncryptedKeystoreBase64, url);

      expect(axios.post).toHaveBeenCalledWith(
        'test-base-url' + url,
        {
          encryptedKeystore: mockEncryptedKeystoreBase64,
        },
        {
          withCredentials: true,
          headers: {
            'Content-Type': 'application/json',
          },
        },
      );
      expect(result).toEqual(mockResponse);
    });

    it('should handle 401 unauthorized error', async () => {
      const unauthorizedError = {
        isAxiosError: true,
        response: {
          status: 401,
          data: { message: 'Unauthorized' },
        },
      };

      vi.mocked(axios.post).mockRejectedValueOnce(unauthorizedError);
      vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      await expect(service.sendEncryptedKeystoreToServer(mockEncryptedKeystoreBase64, url)).rejects.toThrow(
        'Unauthorized: Invalid or expired token',
      );
    });

    it('should handle 403 forbidden error', async () => {
      const forbiddenError = {
        isAxiosError: true,
        response: {
          status: 403,
          data: { message: 'Forbidden' },
        },
      };

      vi.mocked(axios.post).mockRejectedValueOnce(forbiddenError);
      vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      await expect(service.sendEncryptedKeystoreToServer(mockEncryptedKeystoreBase64, url)).rejects.toThrow(
        'Forbidden: Insufficient permissions',
      );
    });

    it('should handle network errors', async () => {
      const networkError = new Error('Network Error');
      vi.mocked(axios.post).mockRejectedValueOnce(networkError);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      await expect(service.sendEncryptedKeystoreToServer(mockEncryptedKeystoreBase64, url)).rejects.toThrow(
        /Failed to send keystore/,
      );
    });
    it('should handle axios errors with an empty response', async () => {
      const errorWithNoResponse = {
        isAxiosError: true,
      };

      vi.mocked(axios.post).mockRejectedValueOnce(errorWithNoResponse);
      vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      await expect(service.sendEncryptedKeystoreToServer(mockEncryptedKeystoreBase64, url)).rejects.toThrow(
        /AxiosError/,
      );
    });
  });

  describe('getKeystore', () => {
    const url = `/downloadKeystore/${mockUserID}/${mockType}`;

    it('should successfully retrieve keystore with valid parameters', async () => {
      const mockResponse = {
        data: mockEncryptedKeystoreBase64,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {},
      };

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      const result = await service.requestEncryptedKeystore(mockUserID, mockType);

      expect(axios.get).toHaveBeenCalledWith('test-base-url' + url, {
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json',
        },
      });
      expect(result).toEqual(mockEncryptedKeystoreBase64);
    });

    it('should handle 401 unauthorized error', async () => {
      const unauthorizedError = {
        isAxiosError: true,
        response: {
          status: 401,
          data: { message: 'Unauthorized' },
        },
      };

      vi.mocked(axios.get).mockRejectedValueOnce(unauthorizedError);
      vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      await expect(service.requestEncryptedKeystore(mockUserID, mockType)).rejects.toThrow(
        'Unauthorized: Invalid or expired token',
      );
    });

    it('should handle 403 forbidden error', async () => {
      const forbiddenError = {
        isAxiosError: true,
        response: {
          status: 403,
          data: { message: 'Forbidden' },
        },
      };

      vi.mocked(axios.get).mockRejectedValueOnce(forbiddenError);
      vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      await expect(service.requestEncryptedKeystore(mockUserID, mockType)).rejects.toThrow(
        'Forbidden: Insufficient permissions',
      );
    });

    it('should handle 404 not found error', async () => {
      const notFoundError = {
        isAxiosError: true,
        response: {
          status: 404,
          data: { message: 'Not Found' },
        },
      };

      vi.mocked(axios.get).mockRejectedValueOnce(notFoundError);
      vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      await expect(service.requestEncryptedKeystore(mockUserID, mockType)).rejects.toThrow(
        'Keystore not found for the specified user',
      );
    });

    it('should handle network errors', async () => {
      const networkError = new Error('Network Error');
      vi.mocked(axios.get).mockRejectedValueOnce(networkError);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      await expect(service.requestEncryptedKeystore(mockUserID, mockType)).rejects.toThrow(
        /Failed to retrive keystore/,
      );
    });

    it('should handle axios errors with an empty response', async () => {
      const errorWithoutResponce = {
        isAxiosError: true,
      };

      vi.mocked(axios.get).mockRejectedValueOnce(errorWithoutResponce);
      vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      await expect(service.requestEncryptedKeystore(mockUserID, mockType)).rejects.toThrow(/AxiosError/);
    });
  });
});
