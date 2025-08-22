import { describe, expect, it } from 'vitest';
import {
  base64ToEncryptedKeystore,
  base64ToEncryptionKeys,
  base64ToIdentityKeys,
  base64ToSearchIndices,
  encryptedKeystoreToBase64,
  encryptionKeysToBase64,
  identityKeysToBase64,
  searchIndicesToBase64,
} from '../../src/keystore/converters';
import { EncryptedKeystore, EncryptionKeys, IdentityKeys, KeystoreType, SearchIndices } from '../../src/utils/types';
import { generateEccKeys } from '../../src/asymmetric-crypto';
import { generateKyberKeys } from '../../src/post-quantum-crypto/kyber768';
import { encryptSymmetrically, genSymmetricCryptoKey } from '../../src/symmetric-crypto';

describe('Test converter functions', () => {
  it('should sucessfully serialize and decerialize an identity key', async () => {
    const keyPair = await generateEccKeys();
    const key: IdentityKeys = {
      userPrivateKey: keyPair.privateKey,
      userPublicKey: keyPair.publicKey,
    };
    const serializedKey = await identityKeysToBase64(key);
    const deserializedKey = await base64ToIdentityKeys(serializedKey);

    expect(deserializedKey).toStrictEqual(key);
  });

  it('should sucessfully serialize and decerialize an encryption key', async () => {
    const keyPair = await generateEccKeys();
    const kyberKeyPair = generateKyberKeys();
    const key: EncryptionKeys = {
      userPrivateKey: keyPair.privateKey,
      userPublicKey: keyPair.publicKey,
      userPrivateKyberKey: kyberKeyPair.secretKey,
      userPublicKyberKey: kyberKeyPair.publicKey,
    };
    const serializedKey = await encryptionKeysToBase64(key);
    const deserializedKey = await base64ToEncryptionKeys(serializedKey);

    expect(deserializedKey).toStrictEqual(key);
  });

  it('should sucessfully serialize and decerialize an encrypted keystore', async () => {
    const sk = await genSymmetricCryptoKey();
    const message = new Uint8Array([1, 2, 3, 4, 5]);
    const cipher = await encryptSymmetrically(sk, message, 'mock-aux', 'userID');

    const keystore: EncryptedKeystore = {
      userID: 'mock-user-id',
      type: KeystoreType.ENCRYPTION,
      encryptedKeys: cipher,
    };
    const serializedKeystore = await encryptedKeystoreToBase64(keystore);
    const deserializedKeystore = await base64ToEncryptedKeystore(serializedKeystore);

    expect(deserializedKeystore).toStrictEqual(keystore);
  });

  it('should sucessfully serialize and decerialize search indices', async () => {
    const indices: SearchIndices = {
      userID: 'mock user ID',
      timestamp: new Date(),
      data: new Uint8Array([42, 13, 250, 4, 0]),
    };
    const serializedIndices = await searchIndicesToBase64(indices);
    const deserializedIndices = await base64ToSearchIndices(serializedIndices);

    expect(deserializedIndices).toStrictEqual(indices);
  });
});
