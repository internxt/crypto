import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  createEncryptionAndRecoveryKeystores,
  openEncryptionKeystore,
  openRecoveryKeystore,
  changePasswordForEncryptionKeystore,
  FailedToOpenEncryptionKeyStore,
  FailedToCreateKeyStores,
  FailedToOpenRecoveryKeyStore,
  FailedToChangePasswordForKeyStore,
} from '../../src/keystore-crypto';
import { XWING_PUBLIC_KEY_LENGTH, XWING_SECRET_KEY_LENGTH } from '../../src/constants';

describe('Test keystore create/open functions', async () => {
  const mockUserEmail = 'mock user email';

  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should throw an error if no password for keystore creation', async () => {
    await expect(createEncryptionAndRecoveryKeystores(mockUserEmail, '')).rejects.toThrow(FailedToCreateKeyStores);
  });

  it('should successfully create and open encryption keystore', async () => {
    const password = 'user password';
    const { encryptionKeystore, recoveryKeystore, recoveryCodes, salt } = await createEncryptionAndRecoveryKeystores(
      mockUserEmail,
      password,
    );
    const resultEnc = await openEncryptionKeystore(encryptionKeystore, password, salt);
    const resultRec = await openRecoveryKeystore(recoveryCodes, recoveryKeystore);

    expect(resultEnc).toStrictEqual(resultRec);
    expect(resultEnc.publicKey).instanceOf(Uint8Array);
    expect(resultEnc.secretKey).instanceOf(Uint8Array);
    expect(resultEnc.publicKey.length).toBe(XWING_PUBLIC_KEY_LENGTH);
    expect(resultEnc.secretKey.length).toBe(XWING_SECRET_KEY_LENGTH);
  });

  it('should throw an error if no password for keystore opening', async () => {
    const password = 'user password';
    const { encryptionKeystore, recoveryKeystore, salt } = await createEncryptionAndRecoveryKeystores(
      mockUserEmail,
      password,
    );

    await expect(openEncryptionKeystore(encryptionKeystore, '', salt)).rejects.toThrow(FailedToOpenEncryptionKeyStore);
    await expect(openRecoveryKeystore('', recoveryKeystore)).rejects.toThrow(FailedToOpenRecoveryKeyStore);
  });

  it('should throw an error if wrong keystore type', async () => {
    const password = 'user password';
    const { encryptionKeystore, recoveryKeystore, recoveryCodes, salt } = await createEncryptionAndRecoveryKeystores(
      mockUserEmail,
      password,
    );

    await expect(openEncryptionKeystore(recoveryKeystore, password, salt)).rejects.toThrow(
      FailedToOpenEncryptionKeyStore,
    );
    await expect(openRecoveryKeystore(recoveryCodes, encryptionKeystore)).rejects.toThrow(FailedToOpenRecoveryKeyStore);
  });

  it('should successfully re-encrypt and open encryption keystore with a new password', async () => {
    const password = 'user password';
    const { encryptionKeystore, salt } = await createEncryptionAndRecoveryKeystores(mockUserEmail, password);
    const resultEnc = await openEncryptionKeystore(encryptionKeystore, password, salt);

    const newPassword = 'a very new user password';
    const { newKeystore, newSalt, keys } = await changePasswordForEncryptionKeystore(
      encryptionKeystore,
      password,
      newPassword,
      salt,
    );

    const resultNew = await openEncryptionKeystore(newKeystore, newPassword, newSalt);

    expect(resultEnc).toStrictEqual(keys);
    expect(resultEnc).toStrictEqual(resultNew);
  });

  it('should throw an error if re-encrypted keystore is opened with old password or salt', async () => {
    const password = 'user password';
    const { encryptionKeystore, salt } = await createEncryptionAndRecoveryKeystores(mockUserEmail, password);
    const resultEnc = await openEncryptionKeystore(encryptionKeystore, password, salt);

    const newPassword = 'a very new user password';
    const { newKeystore, newSalt, keys } = await changePasswordForEncryptionKeystore(
      encryptionKeystore,
      password,
      newPassword,
      salt,
    );

    expect(resultEnc).toStrictEqual(keys);

    await expect(openEncryptionKeystore(newKeystore, password, salt)).rejects.toThrow(FailedToOpenEncryptionKeyStore);

    await expect(openEncryptionKeystore(newKeystore, newPassword, salt)).rejects.toThrow(
      FailedToOpenEncryptionKeyStore,
    );

    await expect(openEncryptionKeystore(newKeystore, password, newSalt)).rejects.toThrow(
      FailedToOpenEncryptionKeyStore,
    );

    await expect(openEncryptionKeystore(encryptionKeystore, newPassword, newSalt)).rejects.toThrow(
      FailedToOpenEncryptionKeyStore,
    );
  });

  it('should throw an error if no password for keystore re-encryption', async () => {
    const password = 'user password';
    const { encryptionKeystore, salt } = await createEncryptionAndRecoveryKeystores(mockUserEmail, password);

    await expect(changePasswordForEncryptionKeystore(encryptionKeystore, password, '', salt)).rejects.toThrow(
      FailedToChangePasswordForKeyStore,
    );
  });
});
