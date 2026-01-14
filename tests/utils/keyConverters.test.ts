import { describe, it, expect } from 'vitest';
import { publicKeyToBase64, base64ToPublicKey, privateKeyToBase64, base64ToPrivateKey } from '../../src/utils';
import { PrivateKeys, PublicKeys } from '../../src/types';
import { generateEccKeys } from '../../src/asymmetric-crypto';
import { generateKyberKeys } from '../../src/post-quantum-crypto';

describe('key converters', () => {
  it('public and private key converter to base64 and back works', async () => {
    const eccKeyPair = await generateEccKeys();
    const kyberKeyPair = await generateKyberKeys();

    const key: PublicKeys = {
      eccPublicKey: eccKeyPair.publicKey,
      kyberPublicKey: kyberKeyPair.publicKey,
    };
    const base64 = await publicKeyToBase64(key);
    const result = await base64ToPublicKey(base64);
    expect(result).toEqual(key);

    const privateKey: PrivateKeys = {
      eccPrivateKey: eccKeyPair.privateKey,
      kyberPrivateKey: kyberKeyPair.secretKey,
    };
    const base64Private = await privateKeyToBase64(privateKey);
    const resultPrivate = await base64ToPrivateKey(base64Private);
    expect(resultPrivate).toEqual(privateKey);
  });

  it('throws error if public key converter to base64 fails', async () => {
    const eccKeyPair = await generateEccKeys();
    const kyberKeyPair = await generateKyberKeys();

    const bad_key: PublicKeys = {
      eccPublicKey: eccKeyPair.privateKey,
      kyberPublicKey: kyberKeyPair.publicKey,
    };
    await expect(publicKeyToBase64(bad_key)).rejects.toThrowError(
      /Failed to convert key of the type PublicKeys to base64/,
    );
  });
  it('throws error if base64 to public key converter fails', async () => {
    const bad_key = 'base base 64 key';
    await expect(base64ToPublicKey(bad_key)).rejects.toThrowError(/Failed to convert base64 to PublicKeys/);
  });
});
