import { describe, expect, it, vi, beforeEach } from 'vitest';
import { createIdentityKeystore, openIdentityKeystore } from '../../src/keystore-crypto';
import { v4 as uuidv4 } from 'uuid';
import { genSymmetricKey } from '../../src/symmetric-crypto';
import sessionStorageService from '../../src/storage-service/sessionStorageService';
import { uint8ArrayToBase64 } from '../../src/utils';

describe('Test user identity keystore functions', async () => {
  const mockUserID = uuidv4();
  const secretKey = await genSymmetricKey();
  const secretKeyBase64 = uint8ArrayToBase64(secretKey);

  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should successfully create and open identity keystore', async () => {
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID).mockReturnValueOnce(secretKeyBase64);
    const encKeystore = await createIdentityKeystore();
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(secretKeyBase64);
    const result = await openIdentityKeystore(encKeystore);
    expect(result.userPrivateKey).instanceOf(CryptoKey);
    expect(result.userPublicKey).instanceOf(CryptoKey);
  });

  it('should throw an error if no base key for keystore creation', async () => {
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

    await expect(createIdentityKeystore()).rejects.toThrowError(/Failed to create identity keystore/);
  });

  it('should throw an error if no base key for keystore opening', async () => {
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID).mockReturnValueOnce(secretKeyBase64);
    const encKeystore = await createIdentityKeystore();

    vi.spyOn(sessionStorageService, 'get').mockResolvedValueOnce('');
    await expect(openIdentityKeystore(encKeystore)).rejects.toThrowError(/Failed to open identity keystore/);
  });
});
