import { describe, expect, it } from 'vitest';
import { encryptSymmetrically, decryptSymmetrically } from '../../src/symmetric/aes';
import { genSymmetricCryptoKey } from '../../src/symmetric';

describe('Test symmetric functions', () => {
  it('should sucessfully encrypt and decrypt', async () => {
    const key = await genSymmetricCryptoKey();
    const nonce = 1;
    const message = new Uint8Array([12, 42, 32, 44, 88, 89, 99, 100]);
    const aux = 'additional data';

    const enc = await encryptSymmetrically(key, nonce, message, aux);
    const result = await decryptSymmetrically(key, enc, aux);

    expect(result).toStrictEqual(message);
  });
});
