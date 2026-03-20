import { describe, expect, it } from 'vitest';
import { encryptSymmetrically, decryptSymmetrically, genSymmetricKey } from '../../src/symmetric-crypto';
import { AES_KEY_BYTE_LENGTH } from '../../src/constants';

describe('Test symmetric functions', () => {
  it('should sucessfully encrypt and decrypt with additional data', async () => {
    const key = genSymmetricKey();
    const message = new Uint8Array([12, 42, 32, 44, 88, 89, 99, 100]);
    const aux = new TextEncoder().encode('additional data');

    const enc = await encryptSymmetrically(key, message, aux);
    const result = await decryptSymmetrically(key, enc, aux);

    expect(result).toStrictEqual(message);

    const enc_2 = await encryptSymmetrically(key, message, aux);
    const result_2 = await decryptSymmetrically(key, enc_2, aux);
    expect(result_2).toStrictEqual(message);
    expect(enc_2).not.toBe(enc);
  });

  it('should sucessfully encrypt and decrypt without additional data', async () => {
    const key = genSymmetricKey();
    const message = new Uint8Array([12, 42, 32, 44, 88, 89, 99, 100]);

    const enc = await encryptSymmetrically(key, message);
    const result = await decryptSymmetrically(key, enc);

    expect(result).toStrictEqual(message);

    const enc_2 = await encryptSymmetrically(key, message);
    const result_2 = await decryptSymmetrically(key, enc_2);
    expect(result_2).toStrictEqual(message);
    expect(enc_2).not.toBe(enc);
  });

  it('should sucessfully generate key', async () => {
    const key = genSymmetricKey();

    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(AES_KEY_BYTE_LENGTH);
  });
});
