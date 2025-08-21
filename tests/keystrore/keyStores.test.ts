import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  createEncryptionAndRecoveryKeystores,
  createIdentityKeystore,
  openEncryptionKeystore,
  openIdentityKeystore,
  openRecoveryKeystore,
} from '../../src/keystore/keyStores';
import { v4 as uuidv4 } from 'uuid';
import { genSymmetricKey } from '../../src/symmetric/keys';
import sessionStorageService from '../../src/utils/sessionStorageService';
import { KYBER768_PUBLIC_KEY_LENGTH, KYBER768_SECRET_KEY_LENGTH, uint8ArrayToBase64 } from '../../src/utils';

describe('Test keystore create/open functions', async () => {
  const mockUserID = uuidv4();
  const secretKey = await genSymmetricKey();
  const secretKyeBase64 = uint8ArrayToBase64(secretKey);

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should successfully create and open identity keystore', async () => {
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID).mockReturnValueOnce(secretKyeBase64);
    const encKeystore = await createIdentityKeystore();
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(secretKyeBase64);
    const result = await openIdentityKeystore(encKeystore);
    expect(result.userPrivateKey).instanceOf(CryptoKey);
    expect(result.userPublicKey).instanceOf(CryptoKey);
  });

  it('should successfully create and open encryption keystore', async () => {
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID).mockReturnValueOnce(secretKyeBase64);
    const { encryptionKeystore, recoveryKeystore, recoveryCodes } = await createEncryptionAndRecoveryKeystores();
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(secretKyeBase64);
    const result_enc = await openEncryptionKeystore(encryptionKeystore);
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(secretKyeBase64);
    const result_rec = await openRecoveryKeystore(recoveryCodes, recoveryKeystore);

    expect(result_enc).toStrictEqual(result_rec);
    expect(result_enc.userPrivateKey).instanceOf(CryptoKey);
    expect(result_enc.userPublicKey).instanceOf(CryptoKey);
    expect(result_enc.userPrivateKyberKey.length).toBe(KYBER768_SECRET_KEY_LENGTH);
    expect(result_enc.userPublicKyberKey.length).toBe(KYBER768_PUBLIC_KEY_LENGTH);
  });

  it('should throw an error if no base key for keystore creation', async () => {
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID);

    await expect(createIdentityKeystore()).rejects.toThrowError(/Identity keystore creation failed/);
    await expect(createEncryptionAndRecoveryKeystores()).rejects.toThrowError(
      /Encryption and recovery keystores creation failed/,
    );
  });

  it('should throw an error if no base key for keystore opening', async () => {
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID).mockReturnValueOnce(secretKyeBase64);
    const encKeystore = await createIdentityKeystore();
    vi.spyOn(sessionStorageService, 'get').mockReturnValueOnce(mockUserID).mockReturnValueOnce(secretKyeBase64);
    const { encryptionKeystore, recoveryKeystore } = await createEncryptionAndRecoveryKeystores();

    vi.spyOn(sessionStorageService, 'get').mockResolvedValueOnce('');

    await expect(openIdentityKeystore(encKeystore)).rejects.toThrowError(/Opening identity keystore failed/);
    await expect(openEncryptionKeystore(encryptionKeystore)).rejects.toThrowError(/Opening encryption keystore failed/);
    await expect(openRecoveryKeystore('', recoveryKeystore)).rejects.toThrowError(/Opening recovery keystore failed/);
  });
});
