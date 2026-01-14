import { describe, expect, it } from 'vitest';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';
import { encryptKeystoreContent, decryptKeystoreContent } from '../../src/keystore-crypto/core';
import { KeystoreType } from '../../src/types';

describe('Test keystore keys functions', () => {
  it('should sucessfully create and open a keystore', async () => {
    const key = await genSymmetricCryptoKey();
    const mockContext = btoa('mock context string');
    const mockUserID = 'mock user ID';
    const mockTag = KeystoreType.ENCRYPTION;
    const keystore = await encryptKeystoreContent(key, mockContext, mockUserID, mockTag);
    const decryptedContent = await decryptKeystoreContent(key, keystore, mockUserID, mockTag);

    expect(mockContext).toBe(decryptedContent);
  });
});
