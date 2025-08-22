import { describe, expect, it } from 'vitest';
import { EmailBody, PublicKeys, User, HybridEncKey, PwdProtectedKey } from '../../src/utils/types';
import {
  emailBodyToBinary,
  binaryToEmailBody,
  publicKeyToBase64,
  base64ToPublicKey,
  pwdProtectedKeyToBase64,
  base64ToPwdProtectedKey,
  encHybridKeyToBase64,
  base64ToEncHybridKey,
  userToBase64,
  base64ToUser,
} from '../../src/email-crypto';
import { generateEccKeys } from '../../src/asymmetric-crypto';
import { generateKyberKeys } from '../../src/post-quantum-crypto/kyber768';
describe('Test email crypto functions', () => {
  it('email converter to binary and back works', async () => {
    const email: EmailBody = {
      text: 'test body',
      date: '2023-06-14T08:11:22.000Z',
      labels: ['test label 1', 'test label2'],
    };
    const binary = emailBodyToBinary(email);
    const result = binaryToEmailBody(binary);
    expect(result).toEqual(email);
  });

  it('throws error if email converter to binary fails', async () => {
    const bad_binary: Uint8Array = new Uint8Array([
      49, 34, 44, 34, 116, 101, 115, 116, 32, 114, 101, 99, 105, 112, 105, 101, 110, 116, 32, 50, 34, 44, 34, 116, 101,
      115, 116, 32, 114, 101, 99, 105, 112, 105, 101, 110, 116, 32, 51, 34, 93, 44, 34,
    ]);
    expect(() => binaryToEmailBody(bad_binary)).toThrowError(/Failed to convert Uint8Array to EmailBody/);
  });

  it('throws error if binary to email converter fails', async () => {
    const bad_email = {
      id: BigInt(42),
      subject: 'test subject',
      body: 'test body',
      sender: 'test sender',
      recipient: ['test recipient 1', 'test recipient 2', 'test recipient 3'],
      date: '2023-06-14T08:11:22.000Z',
      labels: ['test label 1', 'test label2'],
    };
    expect(() => emailBodyToBinary(bad_email as any as EmailBody)).toThrowError(
      /Failed to convert EmailBody to Uint8Array/,
    );
  });

  it('public key converter to base64 and back works', async () => {
    const eccKeyPair = await generateEccKeys();
    const kyberKeyPair = await generateKyberKeys();
    const alice: User = {
      name: 'Alice',
      email: 'alice@email.com',
    };
    const key: PublicKeys = {
      user: alice,
      eccPublicKey: eccKeyPair.publicKey,
      kyberPublicKey: kyberKeyPair.publicKey,
    };
    const base64 = await publicKeyToBase64(key);
    const result = await base64ToPublicKey(base64);
    expect(result).toEqual(key);
  });

  it('user converter to base64 and back works', async () => {
    const alice: User = {
      name: 'Alice',
      email: 'alice@email.com',
    };

    const base64 = await userToBase64(alice);
    const result = await base64ToUser(base64);
    expect(result).toEqual(alice);
  });

  it('throws error if public key converter to base64 fails', async () => {
    const eccKeyPair = await generateEccKeys();
    const kyberKeyPair = await generateKyberKeys();
    const alice: User = {
      name: 'Alice',
      email: 'alice@email.com',
    };
    const bad_key: PublicKeys = {
      user: alice,
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

  it('pwd protected key converter to base64 and back works', async () => {
    const key: PwdProtectedKey = {
      encryptedKey: new Uint8Array([1, 2, 3, 4, 5]),
      salt: new Uint8Array([1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6]),
    };
    const base64 = pwdProtectedKeyToBase64(key);
    const result = base64ToPwdProtectedKey(base64);
    expect(result).toStrictEqual(key);
  });

  it('throws error if pwd protected key to base64 convertion fails', async () => {
    const bad_key = {
      salt: new Uint8Array([1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6]),
    };
    expect(() => pwdProtectedKeyToBase64(bad_key as any)).toThrowError(
      /Failed to convert password-protected key to base64/,
    );
  });

  it('throws error if base64 to pwd protected key convertion fails', async () => {
    const bad_key = 'bad key';
    expect(() => base64ToPwdProtectedKey(bad_key)).toThrowError(/Failed to convert base64 to password-protected key/);
  });

  it('enc hybrid key converter to base64 and back works', async () => {
    const key: HybridEncKey = {
      encryptedKey: new Uint8Array([1, 2, 3, 4, 5]),
      kyberCiphertext: new Uint8Array([1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6]),
    };
    const base64 = encHybridKeyToBase64(key);
    const result = base64ToEncHybridKey(base64);
    expect(result).toStrictEqual(key);
  });

  it('throws error if enc hybrid key to base64 convertion fails', async () => {
    const bad_key = {
      salt: new Uint8Array([1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6]),
    };
    expect(() => encHybridKeyToBase64(bad_key as any)).toThrowError(/Failed to convert hybrid key to base64/);
  });

  it('throws error if base64 to enc hybrid key convertion fails', async () => {
    const bad_key = 'bad key';
    expect(() => base64ToEncHybridKey(bad_key)).toThrowError(/Failed to convert base64 to hybrid key/);
  });
});
