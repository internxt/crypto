import { describe, expect, it, vi } from 'vitest';
import { generateEccKeys, deriveEccBits } from '../../src/asymmetric';
import { CURVE_NAME, ECC_ALGORITHM } from '../../src/utils/constants';

describe('Test ecc functions', () => {
  it('should generate elliptic curves key pair', async () => {
    const keyPair = await generateEccKeys();

    expect(keyPair).toHaveProperty('publicKey');
    expect(keyPair).toHaveProperty('privateKey');
    expect(keyPair.publicKey).toBeInstanceOf(CryptoKey);
    expect(keyPair.privateKey).toBeInstanceOf(CryptoKey);
    expect(keyPair.publicKey.type).toBe('public');
    expect(keyPair.privateKey.type).toBe('private');
    expect(keyPair.privateKey.extractable).toBeFalsy();
    expect(keyPair.privateKey.usages).toContain('deriveBits');

    const alg = keyPair.publicKey.algorithm as EcKeyAlgorithm;
    expect(alg.name).toBe(ECC_ALGORITHM);
    expect(alg.namedCurve).toBe(CURVE_NAME);
  });

  it('should derive the same keys for Bob and Alice', async () => {
    const keysAlice = await generateEccKeys();
    const keysBob = await generateEccKeys();

    const resultAlice = await deriveEccBits(keysBob.publicKey, keysAlice.privateKey);
    const resultBob = await deriveEccBits(keysAlice.publicKey, keysBob.privateKey);

    expect(resultAlice).toStrictEqual(resultBob);
  });

  it('should derive different keys for Bob and Alice and Alice and Eve', async () => {
    const keysAlice = await generateEccKeys();
    const keysBob = await generateEccKeys();
    const keysEve = await generateEccKeys();

    const resultAliceEve = await deriveEccBits(keysEve.publicKey, keysAlice.privateKey);
    const resultAliceBob = await deriveEccBits(keysBob.publicKey, keysAlice.privateKey);

    expect(resultAliceBob).not.toStrictEqual(resultAliceEve);
  });

  it('should throw an error if cannot derive', async () => {
    const keysAlice = await generateEccKeys();

    await expect(deriveEccBits(keysAlice.privateKey, keysAlice.privateKey)).rejects.toThrowError(
      /Failed to derive ECC bits:/,
    );
  });

  it('should throw an error if generateKey fails', async () => {
    const originalGenerateKey = window.crypto.subtle.generateKey;

    window.crypto.subtle.generateKey = vi.fn(() => {
      throw new Error('simulated failure');
    }) as any;

    await expect(generateEccKeys()).rejects.toThrowError('Failed to generate ECC keys: simulated failure');

    window.crypto.subtle.generateKey = originalGenerateKey;
  });
});
