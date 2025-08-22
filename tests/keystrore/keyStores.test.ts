import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  createEncryptionAndRecoveryKeystores,
  createIdentityKeystore,
  decryptCurrentSearchIndices,
  encryptCurrentSearchIndices,
  openEncryptionKeystore,
  openIdentityKeystore,
  openRecoveryKeystore,
} from '../../src/keystore';
import { v4 as uuidv4 } from 'uuid';
import { genSymmetricKey } from '../../src/symmetric-crypto';
import sessionStorageService from '../../src/storage-service/sessionStorageService';
import {
  KYBER768_PUBLIC_KEY_LENGTH,
  KYBER768_SECRET_KEY_LENGTH,
  uint8ArrayToBase64,
  SearchIndices,
} from '../../src/utils';

describe('Test keystore create/open functions', async () => {
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

  it('should successfully create and open encryption keystore', async () => {
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID).mockReturnValueOnce(secretKeyBase64);
    const { encryptionKeystore, recoveryKeystore, recoveryCodes } = await createEncryptionAndRecoveryKeystores();
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(secretKeyBase64);
    const result_enc = await openEncryptionKeystore(encryptionKeystore);
    const result_rec = await openRecoveryKeystore(recoveryCodes, recoveryKeystore);

    expect(result_enc).toStrictEqual(result_rec);
    expect(result_enc.userPrivateKey).instanceOf(CryptoKey);
    expect(result_enc.userPublicKey).instanceOf(CryptoKey);
    expect(result_enc.userPrivateKyberKey.length).toBe(KYBER768_SECRET_KEY_LENGTH);
    expect(result_enc.userPublicKyberKey.length).toBe(KYBER768_PUBLIC_KEY_LENGTH);
  });

  it('should successfully encrypt and decrypt search indices', async () => {
    const indices: SearchIndices = {
      userID: 'mock user ID',
      timestamp: new Date(),
      data: new Uint8Array([42, 13, 250, 4, 0]),
    };
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID).mockReturnValueOnce(secretKeyBase64);
    const encKeystore = await encryptCurrentSearchIndices(indices);
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(secretKeyBase64);
    const result = await decryptCurrentSearchIndices(encKeystore);
    expect(indices).toStrictEqual(result);
  });

  it('should throw an error if no base key for keystore creation', async () => {
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

    await expect(createIdentityKeystore()).rejects.toThrowError(/Failed to create identity keystore/);
    await expect(createEncryptionAndRecoveryKeystores()).rejects.toThrowError(
      /Failed to create encryption and recovery keystores/,
    );
  });

  it('should throw an error if no base key for keystore opening', async () => {
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID).mockReturnValueOnce(secretKeyBase64);
    const encKeystore = await createIdentityKeystore();
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID).mockReturnValueOnce(secretKeyBase64);
    const { encryptionKeystore, recoveryKeystore } = await createEncryptionAndRecoveryKeystores();

    vi.spyOn(sessionStorageService, 'get').mockResolvedValueOnce('');

    await expect(openIdentityKeystore(encKeystore)).rejects.toThrowError(/Failed to open identity keystore/);
    await expect(openEncryptionKeystore(encryptionKeystore)).rejects.toThrowError(/Failed to open encryption keystore/);
    await expect(openRecoveryKeystore('', recoveryKeystore)).rejects.toThrowError(/Failed to open recovery keystore/);
  });
});
