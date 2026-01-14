import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { EncryptedKeystore, KeystoreType } from '../../src/types';
import { encryptedKeystoreToBase64 } from '../../src/utils';
import { getKeyServiceAPI } from '../../src/keystore-service';

vi.mock('axios');

describe('Test keystore send/get service functions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  const mockUserEmail = 'mock email';
  const service = getKeyServiceAPI('test-base-url');
  const mockType = KeystoreType.ENCRYPTION;
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
      const mockType = KeystoreType.ENCRYPTION;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      const result = await service.getEncryptionKeystoreFromServer(mockUserEmail);

      expect(axios.get).toHaveBeenCalledWith(url + `/${mockType}`, credentialField);
      expect(result).toStrictEqual(mockEncryptedKeystore);
    });

    it('should successfully retrieve recovery keystore', async () => {
      const mockType = KeystoreType.RECOVERY;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      const result = await service.getRecoveryKeystoreFromServer(mockUserEmail);

      expect(axios.get).toHaveBeenCalledWith(url + `/${mockType}`, credentialField);
      expect(result).toEqual(mockEncryptedKeystore);
    });
  });
});
