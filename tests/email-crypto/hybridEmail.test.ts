import { describe, expect, it } from 'vitest';
import {
  encryptEmailHybrid,
  decryptEmailHybrid,
  encryptEmailHybridForMultipleRecipients,
  generateEmailKeys,
} from '../../src/email-crypto';

import { EmailBody, HybridEncryptedEmail, HybridEncKey } from '../../src/types';

describe('Test email crypto functions', async () => {
  const email: EmailBody = {
    text: 'test body',
    subject: 'test subject',
  };

  const { secretKey: alicePrivateKeys, publicKey: alicePublicKeys } = await generateEmailKeys();
  const { secretKey: bobPrivateKeys, publicKey: bobPublicKeys } = await generateEmailKeys();

  const bobWithPublicKeys = {
    email: 'bob email',
    publicHybridKey: bobPublicKeys,
  };
  const aliceWithPublicKeys = {
    email: 'alice email',
    publicHybridKey: alicePublicKeys,
  };

  it('should encrypt and decrypt email sucessfully', async () => {
    const encryptedEmail = await encryptEmailHybrid(email, bobWithPublicKeys);

    expect(encryptedEmail.encEmailBody.encSubject).not.toBe(email.subject);
    const decryptedEmail = await decryptEmailHybrid(encryptedEmail, bobPrivateKeys);

    expect(decryptedEmail).toStrictEqual(email);
  });

  it('should throw an error if public key is given instead of the secret one', async () => {
    const bad_recipient = {
      email: 'alice email',
      publicHybridKey: alicePrivateKeys,
    };

    await expect(encryptEmailHybrid(email, bad_recipient)).rejects.toThrowError(
      /Failed to encrypt email body with hybrid encryption/,
    );
  });

  it('should throw an error if not intended recipient', async () => {
    const encryptedEmail = await encryptEmailHybrid(email, bobWithPublicKeys);

    await expect(decryptEmailHybrid(encryptedEmail, alicePrivateKeys)).rejects.toThrowError(
      /Failed to decrypt email with hybrid encryption/,
    );
  });

  it('should throw an error if hybrid email decryption fails', async () => {
    const encKey: HybridEncKey = {
      hybridCiphertext: 'mock kyber ciphertext',
      encryptedKey: 'mock encrypted key',
      encryptedForEmail: 'mock recipient email',
    };
    const bad_encrypted_email: HybridEncryptedEmail = {
      encryptedKey: encKey,
      encEmailBody: {
        encText: 'mock encrypted text',
        encSubject: 'mock encrypted subject',
      },
    };

    await expect(decryptEmailHybrid(bad_encrypted_email, bobPrivateKeys)).rejects.toThrowError(
      /Failed to decrypt email with hybrid encryption/,
    );
  });

  it('should encrypt email to multiple senders sucessfully', async () => {
    const encryptedEmail = await encryptEmailHybridForMultipleRecipients(email, [
      bobWithPublicKeys,
      aliceWithPublicKeys,
    ]);

    expect(encryptedEmail.length).toBe(2);
    expect(encryptedEmail[0].encEmailBody).toBe(encryptedEmail[1].encEmailBody);
  });

  it('should throw an error if encryption to multiple recipients fails', async () => {
    const bad_evePublicKeys = new Uint8Array();

    const bad_eveWithPublicKeys = {
      email: 'eve email',
      name: 'eve',
      publicHybridKey: bad_evePublicKeys,
    };
    await expect(
      encryptEmailHybridForMultipleRecipients(email, [bobWithPublicKeys, bad_eveWithPublicKeys]),
    ).rejects.toThrowError(/Failed to encrypt email to multiple recipients with hybrid encryption/);
  });
});
