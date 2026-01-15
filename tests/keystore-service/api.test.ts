import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { KeystoreType, EncryptedKeystore } from '../../src/types';
import { getKeyServiceAPI } from '../../src/keystore-service';

vi.mock('axios');

describe('Test keystore send/get functions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const mockUserEmail = 'mock email';
  const mockType = KeystoreType.ENCRYPTION;
  const mockEncryptedKeys = {
    publicKeys: {
      eccPublicKeyBase64: 'mock ecc public key base64',
      kyberPublicKeyBase64: 'mock kyber public key base64',
    },
    privateKeys: {
      eccPrivateKeyBase64: 'mock ecc private key base64',
      kyberPrivateKeyBase64: 'mock kyber private key base64',
    },
  };

  const mockEncryptedKeystore: EncryptedKeystore = {
    userEmail: mockUserEmail,
    encryptedKeys: mockEncryptedKeys,
    type: mockType,
  };
  const service = getKeyServiceAPI('test-base-url');

  describe('sendKeystore', () => {
    const url = 'test-base-url/uploadKeystore';

    it('should successfully send keystore with valid parameters', async () => {
      const mockResponse = {
        data: { success: true, message: 'Keystore uploaded successfully' },
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {},
      };

      vi.mocked(axios.post).mockResolvedValue(mockResponse);

      const result = await service.uploadKeystoreToServer(mockEncryptedKeystore);

      expect(axios.post).toHaveBeenCalledWith(
        url,
        {
          encryptedKeystore: mockEncryptedKeystore,
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

      await expect(service.uploadKeystoreToServer(mockEncryptedKeystore)).rejects.toThrow(
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

      await expect(service.uploadKeystoreToServer(mockEncryptedKeystore)).rejects.toThrow(
        'Forbidden: Insufficient permissions',
      );
    });

    it('should handle network errors', async () => {
      const networkError = new Error('Network Error');
      vi.mocked(axios.post).mockRejectedValueOnce(networkError);

      await expect(service.uploadKeystoreToServer(mockEncryptedKeystore)).rejects.toThrow(/Failed to send keystore/);
    });
    it('should handle axios errors with an empty response', async () => {
      const errorWithNoResponse = {
        isAxiosError: true,
      };

      vi.mocked(axios.post).mockRejectedValueOnce(errorWithNoResponse);
      vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);

      await expect(service.uploadKeystoreToServer(mockEncryptedKeystore)).rejects.toThrow(/AxiosError/);
    });
  });

  describe('getKeystore', () => {
    const url = '/downloadKeystore';

    it('should successfully retrieve keystore with valid parameters', async () => {
      const mockResponse = {
        data: mockEncryptedKeystore,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {},
      };

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);

      const result = await service.getKeystoreFromServer(mockUserEmail, mockType);

      expect(axios.get).toHaveBeenCalledWith('test-base-url' + url, {
        withCredentials: true,
        params: { userID: mockUserEmail, keystoreType: mockType },
        headers: {
          'Content-Type': 'application/json',
        },
      });
      expect(result).toEqual(mockEncryptedKeystore);
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

      await expect(service.getKeystoreFromServer(mockUserEmail, mockType)).rejects.toThrow(
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

      await expect(service.getKeystoreFromServer(mockUserEmail, mockType)).rejects.toThrow(
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

      await expect(service.getKeystoreFromServer(mockUserEmail, mockType)).rejects.toThrow(
        'Keystore not found for the specified user',
      );
    });

    it('should handle network errors', async () => {
      const networkError = new Error('Network Error');
      vi.mocked(axios.get).mockRejectedValueOnce(networkError);

      await expect(service.getKeystoreFromServer(mockUserEmail, mockType)).rejects.toThrow(
        /Failed to retrive keystore/,
      );
    });

    it('should handle axios errors with an empty response', async () => {
      const errorWithoutResponce = {
        isAxiosError: true,
      };

      vi.mocked(axios.get).mockRejectedValueOnce(errorWithoutResponce);
      vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);

      await expect(service.getKeystoreFromServer(mockUserEmail, mockType)).rejects.toThrow(/AxiosError/);
    });
  });
});
