import { describe, expect, it, vi } from 'vitest';
import {
  generateEccKeys,
  importPublicKey,
  exportPublicKey,
  exportPrivateKey,
  deriveSecretKey,
  importPrivateKey,
} from '../../src/asymmetric-crypto';
import { CURVE_NAME, ECC_ALGORITHM } from '../../src/constants';
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
    });
    await expect(generateEccKeys()).rejects.toThrowError(
      'Failed to generate elliptic curve key pair: simulated failure',
    );

    window.crypto.subtle.generateKey = vi.fn().mockRejectedValue('mocked error');
    await expect(generateEccKeys()).rejects.toThrowError('Failed to generate elliptic curve key pair: mocked error');

    window.crypto.subtle.generateKey = originalGenerateKey;
  });

  it('should export and import public and secret key', async () => {
    const keyPair = await generateEccKeys();

    const pk = keyPair.publicKey;
    const publicKeyArray = await exportPublicKey(pk);
    const publicKey = await importPublicKey(publicKeyArray);

    await expect(publicKey).toStrictEqual(pk);

    const sk = keyPair.privateKey;
    const secretKeyArray = await exportPrivateKey(sk);
    const secretKey = await importPrivateKey(secretKeyArray);

    await expect(secretKey).toStrictEqual(sk);
  });

  it('should sucessfully serive secret key', async () => {
    const keyPair = await generateEccKeys();
    const keyPairSecond = await generateEccKeys();

    const pk1 = keyPair.publicKey;
    const pk2 = keyPairSecond.publicKey;
    const sk1 = keyPair.privateKey;
    const sk2 = keyPairSecond.privateKey;

    const resultOriginal = await deriveSecretKey(pk1, sk2);
    const result = await deriveSecretKey(pk2, sk1);

    expect(resultOriginal).toStrictEqual(result);
  });

  it('should throw an error if given array is not a key', async () => {
    const badKey = await genSymmetricKey();
    await expect(importPublicKey(badKey)).rejects.toThrowError(/Failed to import public key/);
    await expect(importPrivateKey(badKey)).rejects.toThrowError(/Failed to import private key/);
  });

  it('should throw an error if given CryptKey is not exportable', async () => {
    const keyPair = await generateEccKeys();
    const badPublicKey = keyPair.privateKey;
    await expect(exportPublicKey(badPublicKey)).rejects.toThrowError(/Failed to export public key/);
    const badPrivateKey = keyPair.publicKey;
    await expect(exportPrivateKey(badPrivateKey)).rejects.toThrowError(/Failed to export private key/);
  });

  it('should throw an error if key import fails', async () => {
    const keyPair = await generateEccKeys();
    const pk = keyPair.publicKey;
    const sk = keyPair.privateKey;
    const publicKeyArray = await exportPublicKey(pk);
    const secretKeyArray = await exportPrivateKey(sk);

    const originalImportKey = window.crypto.subtle.importKey;

    window.crypto.subtle.importKey = vi.fn(() => {
      throw new Error('simulated failure');
    });
    await expect(importPublicKey(publicKeyArray)).rejects.toThrowError(
      'Failed to import public key: simulated failure',
    );
    await expect(importPrivateKey(secretKeyArray)).rejects.toThrowError(
      'Failed to import private key: simulated failure',
    );

    window.crypto.subtle.importKey = vi.fn().mockRejectedValue('mocked error');
    await expect(importPublicKey(publicKeyArray)).rejects.toThrowError('Failed to import public key: mocked error');
    await expect(importPrivateKey(secretKeyArray)).rejects.toThrowError('Failed to import private key: mocked error');

    window.crypto.subtle.importKey = originalImportKey;
  });
});
