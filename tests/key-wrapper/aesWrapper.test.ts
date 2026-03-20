import { describe, expect, it } from 'vitest';
import { wrapKey, unwrapKey } from '../../src/key-wrapper';
import { genSymmetricKey } from '../../src/symmetric-crypto';

describe('Test key wrapping functions', () => {
  it('should scuessfully wrap and unwrap key', async () => {
    const wrappingKey = genSymmetricKey();
    const encryptionKey = genSymmetricKey();

    const ciphertext = await wrapKey(encryptionKey, wrappingKey);
    const result = await unwrapKey(ciphertext, wrappingKey);

    expect(result).toStrictEqual(encryptionKey);
  });
});
