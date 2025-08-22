import { describe, expect, it, vi } from 'vitest';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';
import { createKeystore, getBaseKey, getUserID, openKeystore } from '../../src/keystore/core';
import sessionStorageService from '../../src/storage-service/sessionStorageService';
import { base64ToUint8Array, encodeBase64 } from '../../src/utils';

describe('Test keystore keys functions', () => {
  it('should sucessfully create and open a keystore', async () => {
    const key = await genSymmetricCryptoKey();
    const mockContext = encodeBase64('mock context string');
    const mockUserID = 'mock user ID';
    const mockTag = 'mock tag';
    const keystore = await createKeystore(key, 0, mockContext, mockUserID, mockTag);
    const decryptedContent = await openKeystore(key, keystore, mockUserID, mockTag);

    expect(mockContext).toBe(decryptedContent);
  });

  it('should sucessfully return userID', async () => {
    const mockUserID = 'mock user ID';
    const spy = vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);
    const result = getUserID();
    expect(spy).toBeCalledWith('userID');
    expect(result).toBe(mockUserID);
  });

  it('should throw an error if cannot return userID', async () => {
    expect(() => getUserID()).toThrowError(/Failed to get UserID from session storage/);
  });

  it('should sucessfully return base key', async () => {
    const mockBaseKey = 'mock base key';
    const spy = vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockBaseKey);
    const result = getBaseKey();
    expect(spy).toBeCalledWith('baseKey');
    expect(result).toStrictEqual(base64ToUint8Array(mockBaseKey));
  });

  it('should throw an error if cannot return base key', async () => {
    expect(() => getBaseKey()).toThrowError(/Failed to get base key from session storage/);
  });
});
