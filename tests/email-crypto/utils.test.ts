import { describe, expect, it } from 'vitest';
import { EmailBody, Email, HybridEncryptedEmail, HybridEncKey } from '../../src/utils/types';
import { decryptEmailSymmetrically, encryptEmailSymmetrically, getAux } from '../../src/email-crypto/utils';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';

describe('Test email crypto functions', () => {
  it('should encrypt and decrypt email', async () => {
    const emailBody: EmailBody = {
      text: 'test body',
      date: '2023-06-14T08:11:22.000Z',
      labels: ['test label 1', 'test label2'],
    };
    const userAlice = {
      email: 'alice email',
      name: 'alice',
    };

    const userBob = {
      email: 'bob email',
      name: 'bob',
    };

    const email: Email = {
      id: 'test id',
      subject: 'test subject',
      body: emailBody,
      sender: userAlice,
      recipients: [userBob],
      emailChainLength: 2,
    };
    const { encEmail, encryptionKey } = await encryptEmailSymmetrically(email);
    const encKey: HybridEncKey = { kyberCiphertext: new Uint8Array(), encryptedKey: new Uint8Array() };
    const encryptedEmail: HybridEncryptedEmail = {
      ciphertext: encEmail,
      sender: userAlice,
      recipients: [userBob],
      emailChainLength: 2,
      subject: 'test subject',
      encryptedFor: userBob,
      encryptedKey: encKey,
    };
    const result = await decryptEmailSymmetrically(encryptedEmail, encryptionKey);
    expect(result).toEqual(emailBody);
  });

  it('should throw an error if decryption fails', async () => {
    const emailBody: EmailBody = {
      text: 'test body',
      date: '2023-06-14T08:11:22.000Z',
      labels: ['test label 1', 'test label2'],
    };
    const userAlice = {
      email: 'alice email',
      name: 'alice',
    };

    const userBob = {
      email: 'bob email',
      name: 'bob',
    };

    const email: Email = {
      id: 'test id',
      subject: 'test subject',
      body: emailBody,
      sender: userAlice,
      recipients: [userBob],
      emailChainLength: 2,
    };
    const { encEmail } = await encryptEmailSymmetrically(email);
    const encKey: HybridEncKey = { kyberCiphertext: new Uint8Array(), encryptedKey: new Uint8Array() };
    const encryptedEmail: HybridEncryptedEmail = {
      ciphertext: encEmail,
      sender: userAlice,
      recipients: [userBob],
      emailChainLength: 2,
      subject: 'test subject',
      encryptedFor: userBob,
      encryptedKey: encKey,
    };
    const bad_encryptionKey = await genSymmetricCryptoKey();
    await expect(decryptEmailSymmetrically(encryptedEmail, bad_encryptionKey)).rejects.toThrowError(
      /Cannot decrypt email/,
    );
  });

  it('should throw an error if cannot create aux', async () => {
    const bad_email = { subject: BigInt(423) };
    expect(() => getAux(bad_email as any as Email)).toThrowError(/Cannot create aux/);
  });

  it('should throw an error if cannot encrypt', async () => {
    const bad_email: any = {};
    bad_email.self = bad_email;
    await expect(encryptEmailSymmetrically(bad_email)).rejects.toThrowError(/Cannot encrypt email/);
  });
});
