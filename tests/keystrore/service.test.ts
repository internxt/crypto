import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { KeystoreType } from '../../src/utils';
import {
  getEncryptionKeystoreFromServer,
  sendEncryptionKeystoreToServer,
  sendIdentityKeystoreToServer,
  sendIndexKeystoreToServer,
  sendRecoveryKeystoreToServer,
  getIdentityKeystoreFromServer,
  getIndexKeystoreFromServer,
  getRecoveryKeystoreFromServer,
} from '../../src/keystore';
import sessionStorageService from '../../src/utils/sessionStorageService';

vi.mock('axios');

describe('Test keystore send/get service functions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const mockEncryptedKeystore = new Uint8Array([1, 2, 3, 4, 5]);
  const mockUserID = 'userID';
  const tokenField = {
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
    const url = 'test-base-url/uploadKeystore';

    it('should successfully send encryption keystore', async () => {
      const mockType = KeystoreType.ENCRYPTION;
      vi.mocked(axios.post).mockResolvedValue(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

      const result = await sendEncryptionKeystoreToServer(mockEncryptedKeystore);

      expect(axios.post).toHaveBeenCalledWith(
        url,
        {
          encryptedKeystore: mockEncryptedKeystore,
          userID: mockUserID,
          type: mockType,
        },
        tokenField,
      );
      expect(result).toEqual(mockResponse);
    });

    it('should successfully send index keystore', async () => {
      const mockType = KeystoreType.INDEX;
      vi.mocked(axios.post).mockResolvedValue(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);
      const result = await sendIndexKeystoreToServer(mockEncryptedKeystore);

      expect(axios.post).toHaveBeenCalledWith(
        url,
        {
          encryptedKeystore: mockEncryptedKeystore,
          userID: mockUserID,
          type: mockType,
        },
        tokenField,
      );
      expect(result).toEqual(mockResponse);
    });

    it('should successfully send recovery keystore', async () => {
      const mockType = KeystoreType.RECOVERY;
      vi.mocked(axios.post).mockResolvedValue(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);
      const result = await sendRecoveryKeystoreToServer(mockEncryptedKeystore);

      expect(axios.post).toHaveBeenCalledWith(
        url,
        {
          encryptedKeystore: mockEncryptedKeystore,
          userID: mockUserID,
          type: mockType,
        },
        tokenField,
      );
      expect(result).toEqual(mockResponse);
    });
    it('should successfully send identity keystore', async () => {
      const mockType = KeystoreType.IDENTITY;
      vi.mocked(axios.post).mockResolvedValue(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);
      const result = await sendIdentityKeystoreToServer(mockEncryptedKeystore);

      expect(axios.post).toHaveBeenCalledWith(
        url,
        {
          encryptedKeystore: mockEncryptedKeystore,
          userID: mockUserID,
          type: mockType,
        },
        tokenField,
      );
      expect(result).toEqual(mockResponse);
    });
  });

  describe('getKeystore', () => {
    const mockResponse = {
      data: mockEncryptedKeystore,
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
    };

    const url = `test-base-url/downloadKeystore/${mockUserID}`;
    it('should successfully retrieve encryption keystore', async () => {
      const mockType = KeystoreType.ENCRYPTION;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);
      const result = await getEncryptionKeystoreFromServer();

      expect(axios.get).toHaveBeenCalledWith(url + `/${mockType}`, tokenField);
      expect(result).toEqual(mockEncryptedKeystore);
    });

    it('should successfully retrieve identity keystore', async () => {
      const mockType = KeystoreType.IDENTITY;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);
      const result = await getIdentityKeystoreFromServer();

      expect(axios.get).toHaveBeenCalledWith(url + `/${mockType}`, tokenField);
      expect(result).toEqual(mockEncryptedKeystore);
    });

    it('should successfully retrieve recovery keystore', async () => {
      const mockType = KeystoreType.RECOVERY;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);
      const result = await getRecoveryKeystoreFromServer();

      expect(axios.get).toHaveBeenCalledWith(url + `/${mockType}`, tokenField);
      expect(result).toEqual(mockEncryptedKeystore);
    });

    it('should successfully retrieve index keystore', async () => {
      const mockType = KeystoreType.INDEX;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);
      const result = await getIndexKeystoreFromServer();

      expect(axios.get).toHaveBeenCalledWith(url + `/${mockType}`, tokenField);
      expect(result).toEqual(mockEncryptedKeystore);
    });
  });
});
