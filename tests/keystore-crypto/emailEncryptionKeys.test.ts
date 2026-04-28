import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  createEncryptionAndRecoveryKeystores,
  openEncryptionKeystore,
  openRecoveryKeystore,
  changeMnemonicForEncryptionKeystore,
  FailedToOpenEncryptionKeyStore,
  FailedToCreateKeyStores,
  FailedToOpenRecoveryKeyStore,
  FailedToChangeMnemonicForKeyStore,
  InvalidInputKeyStore,
} from '../../src/keystore-crypto';
import { XWING_PUBLIC_KEY_LENGTH, XWING_SECRET_KEY_LENGTH } from '../../src/constants';
import { genMnemonic, uint8ArrayToBase64 } from '../../src/utils';
import { genHybridKeys } from '../../src/hybrid-crypto';

describe('Test keystore create/open functions', async () => {
  const mockUserEmail = 'mock user email';

  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should throw an error if no mnemonic for keystore creation', async () => {
    await expect(createEncryptionAndRecoveryKeystores(mockUserEmail, '')).rejects.toThrow(FailedToCreateKeyStores);
  });

  it('should successfully create and open encryption keystore', async () => {
    const mnemonic = genMnemonic();
    const { encryptionKeystore, recoveryKeystore, recoveryCodes } = await createEncryptionAndRecoveryKeystores(
      mockUserEmail,
      mnemonic,
    );
    const resultEnc = await openEncryptionKeystore(encryptionKeystore, mnemonic);
    const resultRec = await openRecoveryKeystore(recoveryCodes, recoveryKeystore);

    expect(resultEnc).toStrictEqual(resultRec);
    expect(resultEnc.publicKey).instanceOf(Uint8Array);
    expect(resultEnc.secretKey).instanceOf(Uint8Array);
    expect(resultEnc.publicKey.length).toBe(XWING_PUBLIC_KEY_LENGTH);
    expect(resultEnc.secretKey.length).toBe(XWING_SECRET_KEY_LENGTH);
  });

  it('should throw an error if no mnemonic for keystore opening', async () => {
    const mnemonic = genMnemonic();
    const { encryptionKeystore, recoveryKeystore } = await createEncryptionAndRecoveryKeystores(
      mockUserEmail,
      mnemonic,
    );

    await expect(openEncryptionKeystore(encryptionKeystore, '')).rejects.toThrow(FailedToOpenEncryptionKeyStore);
    await expect(openRecoveryKeystore('', recoveryKeystore)).rejects.toThrow(FailedToOpenRecoveryKeyStore);
  });

  it('should throw an error if wrong keystore type', async () => {
    const mnemonic = genMnemonic();
    const { encryptionKeystore, recoveryKeystore, recoveryCodes } = await createEncryptionAndRecoveryKeystores(
      mockUserEmail,
      mnemonic,
    );

    await expect(openEncryptionKeystore(recoveryKeystore, mnemonic)).rejects.toThrow(InvalidInputKeyStore);
    await expect(openRecoveryKeystore(recoveryCodes, encryptionKeystore)).rejects.toThrow(InvalidInputKeyStore);
  });

  it('should successfully re-encrypt and open encryption keystore with a new mnemonic', async () => {
    const mnemonic = genMnemonic();
    const { encryptionKeystore } = await createEncryptionAndRecoveryKeystores(mockUserEmail, mnemonic);
    const resultEnc = await openEncryptionKeystore(encryptionKeystore, mnemonic);

    const newMnemonic = genMnemonic();
    const { newKeystore, keys } = await changeMnemonicForEncryptionKeystore(encryptionKeystore, mnemonic, newMnemonic);

    const resultNew = await openEncryptionKeystore(newKeystore, newMnemonic);

    expect(newMnemonic).not.toEqual(mnemonic);
    expect(resultEnc).toStrictEqual(keys);
    expect(resultEnc).toStrictEqual(resultNew);
  });

  it('should throw an error if re-encrypted keystore is opened with old mnemonic', async () => {
    const mnemonic = genMnemonic();
    const { encryptionKeystore } = await createEncryptionAndRecoveryKeystores(mockUserEmail, mnemonic);
    const resultEnc = await openEncryptionKeystore(encryptionKeystore, mnemonic);

    const newMnemonic = genMnemonic();
    const { newKeystore, keys } = await changeMnemonicForEncryptionKeystore(encryptionKeystore, mnemonic, newMnemonic);

    expect(resultEnc).toStrictEqual(keys);

    await expect(openEncryptionKeystore(newKeystore, mnemonic)).rejects.toThrow(FailedToOpenEncryptionKeyStore);

    await expect(openEncryptionKeystore(encryptionKeystore, newMnemonic)).rejects.toThrow(
      FailedToOpenEncryptionKeyStore,
    );
  });

  it('should throw an error if no mnemonic for keystore re-encryption', async () => {
    const mnemonic = genMnemonic();
    const { encryptionKeystore } = await createEncryptionAndRecoveryKeystores(mockUserEmail, mnemonic);

    await expect(changeMnemonicForEncryptionKeystore(encryptionKeystore, mnemonic, '')).rejects.toThrow(
      FailedToChangeMnemonicForKeyStore,
    );
  });

  it('should throw an error if email or pk changed', async () => {
    const mnemonic = genMnemonic();
    const { encryptionKeystore } = await createEncryptionAndRecoveryKeystores(mockUserEmail, mnemonic);

    const wrongEmailKeystore = { ...encryptionKeystore };
    wrongEmailKeystore.userEmail = 'wrong email';
    await expect(openEncryptionKeystore(wrongEmailKeystore, mnemonic)).rejects.toThrow(FailedToOpenEncryptionKeyStore);

    const wrongPublicKeyKeystore = { ...encryptionKeystore };
    const newKeys = genHybridKeys();
    wrongPublicKeyKeystore.publicKey = uint8ArrayToBase64(newKeys.publicKey);
    await expect(openEncryptionKeystore(wrongPublicKeyKeystore, mnemonic)).rejects.toThrow(
      FailedToOpenEncryptionKeyStore,
    );
  });
});
