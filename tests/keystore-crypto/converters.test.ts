import { describe, expect, it } from 'vitest';
import {
  base64ToEncryptedKeystore,
  base64ToEmailKeys,
  encryptedKeystoreToBase64,
  emailKeysToBase64,
} from '../../src/utils';
import { EncryptedKeystore, EmailKeys, KeystoreType } from '../../src/types';
import { generateEccKeys } from '../../src/asymmetric-crypto';
import { generateKyberKeys } from '../../src/post-quantum-crypto/kyber768';
import { encryptSymmetrically, genSymmetricCryptoKey } from '../../src/symmetric-crypto';

describe('Test converter functions', () => {
  it('should thow an error if not correct key', async () => {
    const serializedKey = 'bad key';
    await expect(base64ToEmailKeys(serializedKey)).rejects.toThrowError(/Failed to convert base64 to encryption key/);
    expect(() => base64ToEncryptedKeystore(serializedKey)).toThrowError(
      /Failed to convert base64 to encrypted keystore/,
    );
  });

  it('should sucessfully serialize and decerialize an encryption key', async () => {
    const keyPair = await generateEccKeys();
    const kyberKeyPair = generateKyberKeys();
    const key: EmailKeys = {
      publicKeys: {
        eccPublicKey: keyPair.publicKey,
        kyberPublicKey: kyberKeyPair.publicKey,
      },
      privateKeys: {
        eccPrivateKey: keyPair.privateKey,
        kyberPrivateKey: kyberKeyPair.secretKey,
      },
    };
    const serializedKey = await emailKeysToBase64(key);
    const deserializedKey = await base64ToEmailKeys(serializedKey);

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
      type: KeystoreType.ENCRYPTION,
      encryptedKeys: cipher,
    };
    const serializedKeystore = await encryptedKeystoreToBase64(keystore);
    const deserializedKeystore = await base64ToEncryptedKeystore(serializedKeystore);

    expect(deserializedKeystore).toStrictEqual(keystore);
  });
});
