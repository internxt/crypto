import { describe, expect, it } from 'vitest';
import {
  encryptEmailHybrid,
  decryptEmailHybrid,
  encryptEmailHybridForMultipleRecipients,
  generateEmailKeys,
  encryptEmailAndSubjectHybrid,
  decryptEmailAndSubjectHybrid,
} from '../../src/email-crypto';

import {
  EmailBody,
  HybridEncryptedEmail,
  HybridEncKey,
  EmailBodyAndSubject,
  HybridEncryptedEmailAndSubject,
} from '../../src/types';
import { EmailHybridDecryptionError, EmailHybridEncryptionError } from '../../src/email-crypto/errors';

describe('Test email crypto functions', async () => {
  const email: EmailBody = {
    text: 'test body',
  };

  const emailAndSubject: EmailBodyAndSubject = {
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
    const decryptedEmail = await decryptEmailHybrid(encryptedEmail, bobPrivateKeys);

    expect(decryptedEmail).toStrictEqual(email);
  });

  it('should encrypt and decrypt email and subject sucessfully', async () => {
    const encryptedEmail = await encryptEmailAndSubjectHybrid(emailAndSubject, bobWithPublicKeys);

    expect(encryptedEmail.encEmailBody?.encSubject).not.toBe(emailAndSubject.subject);
    const decryptedEmail = await decryptEmailAndSubjectHybrid(encryptedEmail, bobPrivateKeys);

    expect(decryptedEmail).toStrictEqual(emailAndSubject);
  });

  it('should throw an error if public key is given instead of the secret one', async () => {
    const badRecipient = {
      email: 'alice email',
      publicHybridKey: alicePrivateKeys,
    };

    await expect(encryptEmailHybrid(email, badRecipient)).rejects.toThrow(EmailHybridEncryptionError);
  });

  it('should throw an error if not intended recipient', async () => {
    const encryptedEmail = await encryptEmailHybrid(email, bobWithPublicKeys);

    await expect(decryptEmailHybrid(encryptedEmail, alicePrivateKeys)).rejects.toThrow(EmailHybridDecryptionError);
  });

  it('should throw an error if hybrid email decryption fails', async () => {
    const encKey: HybridEncKey = {
      hybridCiphertext: 'mock kyber ciphertext',
      encryptedKey: 'mock encrypted key',
      encryptedForEmail: 'mock recipient email',
    };
    const badEncryptedEmail: HybridEncryptedEmail = {
      encryptedKey: encKey,
      encEmailBody: {
        encText: 'mock encrypted text',
      },
    };

    const badEncryptedEmailAndSubject: HybridEncryptedEmailAndSubject = {
      encryptedKey: encKey,
      encEmailBody: {
        encText: 'mock encrypted text',
        encSubject: 'mock encrypted subject',
      },
    };

    await expect(decryptEmailHybrid(badEncryptedEmail, bobPrivateKeys)).rejects.toThrow(EmailHybridDecryptionError);

    await expect(decryptEmailAndSubjectHybrid(badEncryptedEmailAndSubject, bobPrivateKeys)).rejects.toThrow(
      EmailHybridDecryptionError,
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
    const badEvePublicKeys = new Uint8Array();

    const badEveWithPublicKeys = {
      email: 'eve email',
      name: 'eve',
      publicHybridKey: badEvePublicKeys,
    };
    await expect(
      encryptEmailHybridForMultipleRecipients(email, [bobWithPublicKeys, badEveWithPublicKeys]),
    ).rejects.toThrow(EmailHybridEncryptionError);
  });
});
