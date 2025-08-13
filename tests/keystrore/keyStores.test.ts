import { describe, expect, it } from 'vitest';
import {
  createEncryptionKeystore,
  createIdentityKeystore,
  openEncryptionKeystore,
  openIdentityKeystore,
  createRecoveryKeystore,
  openRecoveryKeystore,
} from '../../src/keystore/keyStores';
import { v4 as uuidv4 } from 'uuid';
import { EncryptionKeys, IdentityKeys } from '../../src/utils/types';
import { genSymmetricCryptoKey } from '../../src/symmetric/keys';
import { generateEccKeys } from '../../src/asymmetric/ecc';

describe('Test keystore create/open functions', () => {
  it('should successfully create and open identity keystore', async () => {
    const userID = uuidv4();
    const nonce = 14;
    const keys: IdentityKeys = {
      userPublicKey: 'user public key',
      userPrivateKey: 'user private key',
      serverPublicKey: 'server public key',
    };
    const secretKey = await genSymmetricCryptoKey();
    const encKeystore = await createIdentityKeystore(secretKey, nonce, keys, userID);
    const result = await openIdentityKeystore(secretKey, encKeystore, userID);

    expect(result).toStrictEqual(keys);
  });

  it('should successfully create and open encryption keystore', async () => {
    const userID = uuidv4();
    const nonce = 14;
    const keys: EncryptionKeys = {
      userPublicKey: 'user public key',
      userPrivateKey: 'user private key',
      userPrivateKyberKey: 'user private kyber key',
      userPublicKyberKey: 'user public kyber key',
    };
    const secretKey = await genSymmetricCryptoKey();
    const encKeystore = await createEncryptionKeystore(secretKey, nonce, keys, userID);
    const result = await openEncryptionKeystore(secretKey, encKeystore, userID);

    expect(result).toStrictEqual(keys);
  });

  it('should successfully create and open recovery keystore', async () => {
    const userID = uuidv4();
    const nonce = 14;
    const keys: EncryptionKeys = {
      userPublicKey: 'user public key',
      userPrivateKey: 'user private key',
      userPrivateKyberKey: 'user private kyber key',
      userPublicKyberKey: 'user public kyber key',
    };
    const recoveryKey = await genSymmetricCryptoKey();
    const encKeystore = await createRecoveryKeystore(recoveryKey, nonce, keys, userID);
    const result = await openRecoveryKeystore(recoveryKey, encKeystore, userID);

    expect(result).toStrictEqual(keys);
  });

  it('should throw an error if not symmetric key is given for keystore creation', async () => {
    const userID = uuidv4();
    const nonce = 14;
    const keys: IdentityKeys = {
      userPublicKey: 'user public key',
      userPrivateKey: 'user private key',
      serverPublicKey: 'server public key',
    };
    const encKeys: EncryptionKeys = {
      userPublicKey: 'user public key',
      userPrivateKey: 'user private key',
      userPrivateKyberKey: 'user private kyber key',
      userPublicKyberKey: 'user public kyber key',
    };
    const eccKeys = await generateEccKeys();
    const badKey = eccKeys.privateKey;

    await expect(createIdentityKeystore(badKey, nonce, keys, userID)).rejects.toThrowError(
      /Identity keystore creation failed/,
    );
    await expect(createEncryptionKeystore(badKey, nonce, encKeys, userID)).rejects.toThrowError(
      /Encryption keystore creation failed/,
    );
    await expect(createRecoveryKeystore(badKey, nonce, encKeys, userID)).rejects.toThrowError(
      /Recovery keystore creation failed/,
    );
  });

  it('should throw an error if not symmetric key is given for keystore opening', async () => {
    const userID = uuidv4();
    const nonce = 14;

    const keys: IdentityKeys = {
      userPublicKey: 'user public key',
      userPrivateKey: 'user private key',
      serverPublicKey: 'server public key',
    };
    const encKeys: EncryptionKeys = {
      userPublicKey: 'user public key',
      userPrivateKey: 'user private key',
      userPrivateKyberKey: 'user private kyber key',
      userPublicKyberKey: 'user public kyber key',
    };
    const key = await genSymmetricCryptoKey();
    const identKeystore = await createIdentityKeystore(key, nonce, keys, userID);
    const encKeystore = await createEncryptionKeystore(key, nonce, encKeys, userID);
    const recoveryKeystore = await createRecoveryKeystore(key, nonce, encKeys, userID);

    const eccKeys = await generateEccKeys();
    const badKey = eccKeys.privateKey;

    await expect(openIdentityKeystore(badKey, identKeystore, userID)).rejects.toThrowError(
      /Opening identity keystore failed/,
    );
    await expect(openEncryptionKeystore(badKey, encKeystore, userID)).rejects.toThrowError(
      /Opening encryption keystore failed/,
    );
    await expect(openRecoveryKeystore(badKey, recoveryKeystore, userID)).rejects.toThrowError(
      /Opening recovery keystore failed/,
    );
  });
});
