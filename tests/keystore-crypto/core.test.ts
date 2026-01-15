import { describe, expect, it } from 'vitest';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';
import { encryptKeystoreContent, decryptKeystoreContent } from '../../src/keystore-crypto/core';
import { KeystoreType } from '../../src/types';
import { generateEmailKeys } from '../../src/email-crypto';

describe('Test keystore keys functions', () => {
  it('should sucessfully create and open a keystore', async () => {
    const key = await genSymmetricCryptoKey();
    const mockKeys = await generateEmailKeys();
    const mockUserEmail = 'mock user email';
    const mockTag = KeystoreType.ENCRYPTION;
    const keystore = await encryptKeystoreContent(key, mockKeys, mockUserEmail, mockTag);
    const decryptedContent = await decryptKeystoreContent(key, keystore);

    expect(mockKeys).toEqual(decryptedContent);
  });
});
