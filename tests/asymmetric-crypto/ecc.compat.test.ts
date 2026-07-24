import { describe, expect, it } from 'vitest';
import * as webEcc from '../../src/asymmetric-crypto/ellipticCurve';
import * as nativeEcc from '../../src/asymmetric-crypto/ellipticCurve.native';

describe('ellipticCurve.ts vs ellipticCurve.native.ts parity', () => {
  it('web-generated keys work with native deriveSecretKey', async () => {
    const keysAlice = await webEcc.generateEccKeys();
    const keysBob = await webEcc.generateEccKeys();

    const resultAlice = await nativeEcc.deriveSecretKey(keysAlice.secretKey, keysBob.publicKey);
    const resultBob = await webEcc.deriveSecretKey(keysBob.secretKey, keysAlice.publicKey);

    expect(resultAlice).toStrictEqual(resultBob);
  });

  it('native-generated keys work with web deriveSecretKey', async () => {
    const keysAlice = await nativeEcc.generateEccKeys();
    const keysBob = await nativeEcc.generateEccKeys();

    const resultAlice = await webEcc.deriveSecretKey(keysAlice.secretKey, keysBob.publicKey);
    const resultBob = await nativeEcc.deriveSecretKey(keysBob.secretKey, keysAlice.publicKey);

    expect(resultAlice).toStrictEqual(resultBob);
  });

  it('cross-implementation derivation matches same-implementation derivation', async () => {
    const keysAlice = await webEcc.generateEccKeys();
    const keysBob = await nativeEcc.generateEccKeys();

    const crossResult = await webEcc.deriveSecretKey(keysAlice.secretKey, keysBob.publicKey);
    const nativeSideResult = await nativeEcc.deriveSecretKey(keysBob.secretKey, keysAlice.publicKey);

    expect(crossResult).toStrictEqual(nativeSideResult);
  });

  it('both throw on invalid public key with the same error', async () => {
    const keysAlice = await webEcc.generateEccKeys();

    await expect(webEcc.deriveSecretKey(keysAlice.secretKey, new Uint8Array())).rejects.toThrowError(
      /Failed to derive elliptic curve secret key/,
    );
    await expect(nativeEcc.deriveSecretKey(keysAlice.secretKey, new Uint8Array())).rejects.toThrowError(
      /Failed to derive elliptic curve secret key/,
    );
  });

  it('exposes the same public API surface', () => {
    expect(Object.keys(webEcc).sort()).toStrictEqual(Object.keys(nativeEcc).sort());
  });
});