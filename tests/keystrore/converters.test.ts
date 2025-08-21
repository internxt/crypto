import { describe, expect, it } from 'vitest';
import {
  base64ToEncryptedKeystore,
  base64ToEncryptionKeys,
  base64ToIdentityKeys,
  encryptedKeystoreToBase64,
  encryptionKeysToBase64,
  identityKeysToBase64,
} from '../../src/keystore/converters';
import { EncryptedKeystore, EncryptionKeys, IdentityKeys, KeystoreType } from '../../src/utils/types';
import { generateEccKeys } from '../../src/asymmetric/keys';
import { generateKyberKeys } from '../../src/post-quantum/kyber768';
import { encryptSymmetrically, genSymmetricCryptoKey } from '../../src/symmetric';

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
    const cipher = await encryptSymmetrically(sk, 0, message, 'mock-aux');

    const keystore: EncryptedKeystore = {
      userID: 'mock-user-id',
      type: KeystoreType.ENCRYPTION,
      encryptedKeys: cipher,
    };
    const serializedKeystore = await encryptedKeystoreToBase64(keystore);
    const deserializedKeystore = await base64ToEncryptedKeystore(serializedKeystore);

    expect(deserializedKeystore).toStrictEqual(keystore);
  });
});
