import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { KeystoreType } from '../../src/utils';
import {
  getEncryptionKeystore,
  sendEncryptionKeystore,
  sendIdentityKeystore,
  sendIndexKeystore,
  sendRecoveryKeystore,
  getIdentityKeystore,
  getIndexKeystore,
  getRecoveryKeystore,
} from '../../src/keystore'; // Adjust import path as needed

vi.mock('axios');

describe('Test keystore send/get service functions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const mockEncryptedKeystore = new Uint8Array([1, 2, 3, 4, 5]);
  const mockUserID = 'userID';
  const mockToken = 'valid-token';
  const tokenField = {
    headers: {
      Authorization: `Bearer ${mockToken}`,
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

    it('should successfully send encryption keystore', async () => {
      const mockType = KeystoreType.ENCRYPTION;
      vi.mocked(axios.post).mockResolvedValue(mockResponse);
      const result = await sendEncryptionKeystore(mockEncryptedKeystore, mockUserID, mockToken);

      expect(axios.post).toHaveBeenCalledWith(
        `/api/keystore/${mockType}`,
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
      const result = await sendIndexKeystore(mockEncryptedKeystore, mockUserID, mockToken);

      expect(axios.post).toHaveBeenCalledWith(
        `/api/keystore/${mockType}`,
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
      const result = await sendRecoveryKeystore(mockEncryptedKeystore, mockUserID, mockToken);

      expect(axios.post).toHaveBeenCalledWith(
        `/api/keystore/${mockType}`,
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
      const result = await sendIdentityKeystore(mockEncryptedKeystore, mockUserID, mockToken);

      expect(axios.post).toHaveBeenCalledWith(
        `/api/keystore/${mockType}`,
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

    it('should successfully retrieve encryption keystore', async () => {
      const mockType = KeystoreType.ENCRYPTION;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      const result = await getEncryptionKeystore(mockUserID, mockToken);

      expect(axios.get).toHaveBeenCalledWith(`/api/keystore/${mockUserID}/${mockType}`, tokenField);
      expect(result).toEqual(mockEncryptedKeystore);
    });

    it('should successfully retrieve identity keystore', async () => {
      const mockType = KeystoreType.IDENTITY;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      const result = await getIdentityKeystore(mockUserID, mockToken);

      expect(axios.get).toHaveBeenCalledWith(`/api/keystore/${mockUserID}/${mockType}`, tokenField);
      expect(result).toEqual(mockEncryptedKeystore);
    });

    it('should successfully retrieve recovery keystore', async () => {
      const mockType = KeystoreType.RECOVERY;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      const result = await getRecoveryKeystore(mockUserID, mockToken);

      expect(axios.get).toHaveBeenCalledWith(`/api/keystore/${mockUserID}/${mockType}`, tokenField);
      expect(result).toEqual(mockEncryptedKeystore);
    });

    it('should successfully retrieve index keystore', async () => {
      const mockType = KeystoreType.INDEX;

      vi.mocked(axios.get).mockResolvedValueOnce(mockResponse);
      const result = await getIndexKeystore(mockUserID, mockToken);

      expect(axios.get).toHaveBeenCalledWith(`/api/keystore/${mockUserID}/${mockType}`, tokenField);
      expect(result).toEqual(mockEncryptedKeystore);
    });
  });
});
