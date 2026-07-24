import { describe, expect, it } from 'vitest';
import * as webAes from '../../src/symmetric-crypto/aes';
import * as nativeAes from '../../src/symmetric-crypto/aes.native';
import { genSymmetricKey } from '../../src/symmetric-crypto';

describe('aes.ts vs aes.native.ts parity', () => {
  const key = genSymmetricKey();
  const message = new Uint8Array([12, 42, 32, 44, 88, 89, 99, 100]);
  const aux = new TextEncoder().encode('additional data');

  it('web can decrypt what native encrypted', async () => {
    const enc = await nativeAes.encryptSymmetrically(key, message, aux);
    const result = await webAes.decryptSymmetrically(key, enc, aux);
    expect(result).toStrictEqual(message);
  });

  it('native can decrypt what web encrypted', async () => {
    const enc = await webAes.encryptSymmetrically(key, message, aux);
    const result = await nativeAes.decryptSymmetrically(key, enc, aux);
    expect(result).toStrictEqual(message);
  });

  it('both round-trip identically without aad', async () => {
    const encWeb = await webAes.encryptSymmetrically(key, message);
    const encNative = await nativeAes.encryptSymmetrically(key, message);

    expect(await webAes.decryptSymmetrically(key, encNative)).toStrictEqual(message);
    expect(await nativeAes.decryptSymmetrically(key, encWeb)).toStrictEqual(message);
  });

  it('exposes the same public API surface', () => {
    expect(Object.keys(webAes).sort()).toStrictEqual(Object.keys(nativeAes).sort());
  });
});