import { describe, expect, it, vi } from 'vitest';
import { generateEccKeys, importPublicKey, exportPublicKey, deriveSecretKey } from '../../src/asymmetric-crypto';
import { CURVE_NAME, ECC_ALGORITHM } from '../../src/utils';
import { genSymmetricKey } from '../../src/symmetric-crypto';

describe('Test ecc functions', () => {
  it('should generate elliptic curves key pair', async () => {
    const keyPair = await generateEccKeys();

    expect(keyPair).toHaveProperty('publicKey');
    expect(keyPair).toHaveProperty('privateKey');
    expect(keyPair.publicKey).toBeInstanceOf(CryptoKey);
    expect(keyPair.privateKey).toBeInstanceOf(CryptoKey);
    expect(keyPair.publicKey.type).toBe('public');
    expect(keyPair.privateKey.type).toBe('private');
    expect(keyPair.privateKey.extractable).toBeTruthy();
    expect(keyPair.privateKey.usages).toContain('deriveBits');

    const alg = keyPair.publicKey.algorithm as EcKeyAlgorithm;
    expect(alg.name).toBe(ECC_ALGORITHM);
    expect(alg.namedCurve).toBe(CURVE_NAME);
  });

  it('should throw an error if generateKey fails', async () => {
    const originalGenerateKey = window.crypto.subtle.generateKey;

    window.crypto.subtle.generateKey = vi.fn(() => {
      throw new Error('simulated failure');
    }) as any;

    await expect(generateEccKeys()).rejects.toThrowError(
      'Failed to generate elliptic curve key pair: simulated failure',
    );

    window.crypto.subtle.generateKey = originalGenerateKey;
  });

  it('should export and import public key', async () => {
    const keyPair = await generateEccKeys();

    const originalPublicKey = keyPair.publicKey;
    const publicKeyArray = await exportPublicKey(originalPublicKey);
    const publicKey = await importPublicKey(publicKeyArray);

    await expect(publicKey).toStrictEqual(originalPublicKey);

    const keyPairSecond = await generateEccKeys();
    const resultOriginal = await deriveSecretKey(originalPublicKey, keyPairSecond.privateKey);
    const result = await deriveSecretKey(publicKey, keyPairSecond.privateKey);

    expect(resultOriginal).toStrictEqual(result);
  });

  it('should throw an error if given array is not public key', async () => {
    const badPublicKey = await genSymmetricKey();
    await expect(importPublicKey(badPublicKey)).rejects.toThrowError(/Failed to import public key/);
  });

  it('should throw an error if given CryptKey is not exportable', async () => {
    const keyPair = await generateEccKeys();
    const badPublicKey = keyPair.privateKey;
    await expect(exportPublicKey(badPublicKey)).rejects.toThrowError(/Failed to export public key/);
  });
});
