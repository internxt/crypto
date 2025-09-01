import { describe, expect, it } from 'vitest';
import { EmailBody, Email, HybridEncryptedEmail, HybridEncKey, User } from '../../src/types';
import { decryptEmailSymmetrically, encryptEmailSymmetrically, getAux } from '../../src/email-crypto/core';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';
import { usersToRecipients } from '../../src/email-crypto';

describe('Test email crypto functions', () => {
  it('should encrypt and decrypt email', async () => {
    const emailBody: EmailBody = {
      text: 'test body',
      date: '2023-06-14T08:11:22.000Z',
      labels: ['test label 1', 'test label2'],
    };
    const userAlice: User = {
      email: 'alice email',
      name: 'alice',
      id: '1',
    };

    const userBob: User = {
      email: 'bob email',
      name: 'bob',
      id: '2',
    };

    const email: Email = {
      id: 'test id',
      subject: 'test subject',
      body: emailBody,
      sender: userAlice,
      recipients: usersToRecipients([userBob]),
      replyToEmailID: 2,
    };
    const { encEmail, encryptionKey } = await encryptEmailSymmetrically(email);
    const encKey: HybridEncKey = { kyberCiphertext: new Uint8Array(), encryptedKey: new Uint8Array() };
    const encryptedEmail: HybridEncryptedEmail = {
      ciphertext: encEmail,
      sender: userAlice,
      recipients: usersToRecipients([userBob]),
      replyToEmailID: 2,
      subject: 'test subject',
      encryptedFor: userBob.id,
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
    const userAlice: User = {
      email: 'alice email',
      name: 'alice',
      id: '1',
    };

    const userBob = {
      email: 'bob email',
      name: 'bob',
      id: '2',
    };

    const email: Email = {
      id: 'test id',
      subject: 'test subject',
      body: emailBody,
      sender: userAlice,
      recipients: usersToRecipients([userBob]),
      replyToEmailID: 2,
    };
    const { encEmail } = await encryptEmailSymmetrically(email);
    const encKey: HybridEncKey = { kyberCiphertext: new Uint8Array(), encryptedKey: new Uint8Array() };
    const encryptedEmail: HybridEncryptedEmail = {
      ciphertext: encEmail,
      sender: userAlice,
      recipients: usersToRecipients([userBob]),
      replyToEmailID: 2,
      subject: 'test subject',
      encryptedFor: userBob.id,
      encryptedKey: encKey,
    };
    const bad_encryptionKey = await genSymmetricCryptoKey();
    await expect(decryptEmailSymmetrically(encryptedEmail, bad_encryptionKey)).rejects.toThrowError(
      /Failed to symmetrically decrypt email/,
    );
  });

  it('should throw an error if cannot create aux', async () => {
    const bad_email = { subject: BigInt(423) };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => getAux(bad_email as any as Email)).toThrowError(/Failed to create aux/);
  });

  it('should throw an error if cannot encrypt', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const bad_email: any = {};
    bad_email.self = bad_email;
    await expect(encryptEmailSymmetrically(bad_email)).rejects.toThrowError(/Failed to symmetrically encrypt email/);
  });
});
