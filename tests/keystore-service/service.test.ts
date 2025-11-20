import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { EncryptedKeystore, KEYSTORE_TAGS } from '../../src/types';
import { encryptedKeystoreToBase64 } from '../../src/utils';
import { getKeyServiceAPI } from '../../src/keystore-service';
import sessionStorageService from '../../src/storage-service/sessionStorageService';

vi.mock('axios');

describe('Test keystore send/get service functions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  const mockUserEmail = 'mock email';
  const service = getKeyServiceAPI('test-base-url');
  const mockType = KEYSTORE_TAGS.ENCRYPTION;
  const mockCiphertext = new Uint8Array([1, 2, 3, 4, 5]);
  const mockEncryptedKeystore: EncryptedKeystore = {
    userEmail: mockUserEmail,
    encryptedKeys: mockCiphertext,
    type: mockType,
  };
  const mockEncryptedKeystoreBase64 = encryptedKeystoreToBase64(mockEncryptedKeystore);

  const credentialField = {
    withCredentials: true,
    headers: {
      'Content-Type': 'application/json',
    },
  };

  describe('sendKeystore', () => {
    const mockResponse = {
      data: { success: true, message: 'Keystore uploaded successfully' },
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    };
    const url = `test-base-url/uploadKeystore/${mockUserEmail}`;

    it('should successfully send an encryption keystore', async () => {
      vi.mocked(axios.post).mockResolvedValue(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserEmail);

      const result = await service.uploadKeystoreToServer(mockEncryptedKeystore);

      expect(axios.post).toHaveBeenCalledWith(
        url + `/${mockType}`,
        {
          encryptedKeystore: mockEncryptedKeystoreBase64,
        },
        credentialField,
      );
      expect(result).toEqual(mockResponse);
    });

    it('should succethrow an error if cannot send an encryption keystore', async () => {
      const unauthorizedError = {
        isAxiosError: true,
        response: {
          status: 401,
          data: { message: 'Unauthorized' },
        },
      };

      vi.mocked(axios.post).mockRejectedValueOnce(unauthorizedError);
      vi.mocked(axios.isAxiosError).mockReturnValueOnce(true);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserEmail);

      await expect(service.uploadKeystoreToServer(mockEncryptedKeystore)).rejects.toThrow(
        /Failed to upload keystore to the server/,
      );
    });
  });

  describe('getKeystore', () => {
    const mockResponse = {
      data: mockEncryptedKeystoreBase64,
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    };

    const url = `test-base-url/downloadKeystore/${mockUserEmail}`;
    it('should successfully retrieve encryption keystore', async () => {
      const mockType = KEYSTORE_TAGS.ENCRYPTION;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserEmail);
      const result = await service.getEncryptionKeystoreFromServer();

      expect(axios.get).toHaveBeenCalledWith(url + `/${mockType}`, credentialField);
      expect(result).toStrictEqual(mockEncryptedKeystore);
    });

    it('should successfully retrieve identity keystore', async () => {
      const mockType = KEYSTORE_TAGS.IDENTITY;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserEmail);
      const result = await service.getIdentityKeystoreFromServer();

      expect(axios.get).toHaveBeenCalledWith(url + `/${mockType}`, credentialField);
      expect(result).toEqual(mockEncryptedKeystore);
    });

    it('should successfully retrieve recovery keystore', async () => {
      const mockType = KEYSTORE_TAGS.RECOVERY;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserEmail);
      const result = await service.getRecoveryKeystoreFromServer();

      expect(axios.get).toHaveBeenCalledWith(url + `/${mockType}`, credentialField);
      expect(result).toEqual(mockEncryptedKeystore);
    });

    it('should successfully retrieve index keystore', async () => {
      const mockType = KEYSTORE_TAGS.INDEX;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserEmail);
      const result = await service.getIndexKeystoreFromServer();

      expect(axios.get).toHaveBeenCalledWith(url + `/${mockType}`, credentialField);
      expect(result).toEqual(mockEncryptedKeystore);
    });

    it('should throw an error if cannot retrive a keystore', async () => {
      const networkError = new Error('Network Error');
      vi.mocked(axios.get).mockRejectedValueOnce(networkError);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserEmail);

      await expect(service.getIndexKeystoreFromServer()).rejects.toThrow(/Failed to retrieve keystore from the server/);
    });
  });
});
