import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { KeystoreType } from '../../src/utils';
import { sendKeystore, getKeystoreFromServer } from '../../src/keystore/api';
import sessionStorageService from '../../src/utils/sessionStorageService';

vi.mock('axios');

describe('Test keystore send/get functions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const mockUserID = 'userID';
  const mockKeystore = new Uint8Array([1, 2, 3, 4, 5]);
  const mockType = KeystoreType.ENCRYPTION;
  const url = 'test-base-url/uploadKeystore';

  describe('sendKeystore', () => {
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

      const result = await sendKeystore(mockKeystore, mockType);

      expect(axios.post).toHaveBeenCalledWith(
        url,
        {
          encryptedKeystore: mockKeystore,
          userID: mockUserID,
          type: mockType,
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

      await expect(sendKeystore(mockKeystore, mockType)).rejects.toThrow('Unauthorized: Invalid or expired token');
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

      await expect(sendKeystore(mockKeystore, mockType)).rejects.toThrow('Forbidden: Insufficient permissions');
    });

    it('should handle network errors', async () => {
      const networkError = new Error('Network Error');
      vi.mocked(axios.post).mockRejectedValueOnce(networkError);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      await expect(sendKeystore(mockKeystore, mockType)).rejects.toThrow('Network Error');
    });
    it('should handle axios errors with an empty response', async () => {
      const errorWithNoResponse = {
        isAxiosError: true,
      };

      vi.mocked(axios.post).mockRejectedValueOnce(errorWithNoResponse);
      vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      await expect(sendKeystore(mockKeystore, mockType)).rejects.toThrow(/AxiosError: Error sending keystore/);
    });
  });

  describe('getKeystore', () => {
    const url = `test-base-url/downloadKeystore/${mockUserID}`;

    it('should successfully retrieve keystore with valid parameters', async () => {
      const mockResponse = {
        data: mockKeystore,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {},
      };

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      const result = await getKeystoreFromServer(mockType);

      expect(axios.get).toHaveBeenCalledWith(url + `/${mockType}`, {
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json',
        },
      });
      expect(result).toEqual(mockKeystore);
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

      await expect(getKeystoreFromServer(mockType)).rejects.toThrow('Unauthorized: Invalid or expired token');
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

      await expect(getKeystoreFromServer(mockType)).rejects.toThrow('Forbidden: Insufficient permissions');
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

      await expect(getKeystoreFromServer(mockType)).rejects.toThrow('Keystore not found for the specified user');
    });

    it('should handle network errors', async () => {
      const networkError = new Error('Network Error');
      vi.mocked(axios.get).mockRejectedValueOnce(networkError);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      await expect(getKeystoreFromServer(mockType)).rejects.toThrow('Network Error');
    });

    it('should handle axios errors with an empty response', async () => {
      const errorWithoutResponce = {
        isAxiosError: true,
      };

      vi.mocked(axios.get).mockRejectedValueOnce(errorWithoutResponce);
      vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      await expect(getKeystoreFromServer(mockType)).rejects.toThrow(/AxiosError: Error retrieving keystore/);
    });
  });
});
