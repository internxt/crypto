import { describe, expect, it } from 'vitest';
import {
  base64ToEncryptedKeystore,
  base64ToEncryptionKeys,
  base64ToIdentityKeys,
  encryptedKeystoreToBase64,
  encryptionKeysToBase64,
  identityKeysToBase64,
} from '../../src/utils';
import { EncryptedKeystore, EncryptionKeys, IdentityKeys, KEYSTORE_TAGS } from '../../src/types';
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

  it('should thow an error if not correct key', async () => {
    const serializedKey = 'bad key';
    await expect(base64ToIdentityKeys(serializedKey)).rejects.toThrowError(/Failed convert base64 to idenity key/);
    await expect(base64ToEncryptionKeys(serializedKey)).rejects.toThrowError(
      /Failed to convert base64 to encryption key/,
    );
    expect(() => base64ToEncryptedKeystore(serializedKey)).toThrowError(
      /Failed to convert base64 to encrypted keystore/,
    );
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
    const aux = new Uint8Array([2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const freeFiled = new Uint8Array([7, 7, 7]);
    const cipher = await encryptSymmetrically(sk, message, aux, freeFiled);

    const keystore: EncryptedKeystore = {
      userEmail: 'mock-user-email',
      type: KEYSTORE_TAGS.ENCRYPTION,
      encryptedKeys: cipher,
    };
    const serializedKeystore = await encryptedKeystoreToBase64(keystore);
    const deserializedKeystore = await base64ToEncryptedKeystore(serializedKeystore);

    expect(deserializedKeystore).toStrictEqual(keystore);
  });
});
