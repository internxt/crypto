import { describe, expect, it } from 'vitest';
import { encryptSymmetrically, decryptSymmetrically, genSymmetricCryptoKey } from '../../src/symmetric-crypto';

describe('Test symmetric functions', () => {
  it('should sucessfully encrypt and decrypt', async () => {
    const key = await genSymmetricCryptoKey();
    const message = new Uint8Array([12, 42, 32, 44, 88, 89, 99, 100]);
    const aux = new TextEncoder().encode('additional data');
    const freeField = new Uint8Array([1, 2, 3]);

    const enc = await encryptSymmetrically(key, message, aux, freeField);
    const result = await decryptSymmetrically(key, enc, aux);

    expect(result).toStrictEqual(message);

    const enc_2 = await encryptSymmetrically(key, message, aux);
    const result_2 = await decryptSymmetrically(key, enc_2, aux);
    expect(result_2).toStrictEqual(message);
    expect(enc_2).not.toBe(enc);
  });
});
