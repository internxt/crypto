import { describe, expect, it, vi, beforeEach } from 'vitest';
import { decryptCurrentSearchIndices, encryptCurrentSearchIndices } from '../../src/keystore-crypto';
import { v4 as uuidv4 } from 'uuid';
import { genSymmetricKey } from '../../src/symmetric-crypto';
import sessionStorageService from '../../src/storage-service/sessionStorageService';
import { uint8ArrayToBase64, SearchIndices } from '../../src/utils';

describe('Test keystore create/open functions', async () => {
  const mockUserID = uuidv4();
  const secretKey = await genSymmetricKey();
  const secretKeyBase64 = uint8ArrayToBase64(secretKey);
  const indices: SearchIndices = {
    userID: 'mock user ID',
    timestamp: new Date(),
    data: new Uint8Array([42, 13, 250, 4, 0]),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should successfully encrypt and decrypt search indices', async () => {
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID).mockReturnValueOnce(secretKeyBase64);
    const encKeystore = await encryptCurrentSearchIndices(indices);
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(secretKeyBase64);
    const result = await decryptCurrentSearchIndices(encKeystore);
    expect(indices).toStrictEqual(result);
  });

  it('should throw an error if no base key for encryption', async () => {
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);
    await expect(encryptCurrentSearchIndices(indices)).rejects.toThrowError(/Failed to encrypt search indices/);
  });

  it('should throw an error if no base key for decryption', async () => {
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID).mockReturnValueOnce(secretKeyBase64);
    const encKeystore = await encryptCurrentSearchIndices(indices);

    vi.spyOn(sessionStorageService, 'get').mockResolvedValueOnce('');

    await expect(decryptCurrentSearchIndices(encKeystore)).rejects.toThrowError(/Failed to decrypt search index/);
  });
});
