import { describe, expect, it } from 'vitest';
import {
  encryptEmailHybrid,
  decryptEmailHybrid,
  encryptEmailHybridForMultipleRecipients,
  generateEmailKeys,
  encryptEmailAndSubjectHybrid,
  decryptEmailAndSubjectHybrid,
  encryptEmailAndSubjectHybridForMultipleRecipients,
} from '../../src/email-crypto';

import {
  EmailBody,
  HybridEncryptedEmail,
  HybridEncKey,
  EmailBodyAndSubject,
  HybridEncryptedEmailAndSubject,
  RecipientWithPublicKey,
} from '../../src/types';
import {
  EmailHybridDecryptionError,
  EmailHybridEncryptionError,
  EmailSymmetricDecryptionError,
  InvalidInputEmail,
} from '../../src/email-crypto/errors';

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
    await expect(encryptEmailAndSubjectHybrid(emailAndSubject, badRecipient)).rejects.toThrow(
      EmailHybridEncryptionError,
    );
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

  it('should encrypt email and subject to multiple senders sucessfully', async () => {
    const encryptedEmail = await encryptEmailAndSubjectHybridForMultipleRecipients(emailAndSubject, [
      bobWithPublicKeys,
      aliceWithPublicKeys,
    ]);

    expect(encryptedEmail.length).toBe(2);
    expect(encryptedEmail[0].encEmailBody).toBe(encryptedEmail[1].encEmailBody);

    const emailDecryptedByBob = await decryptEmailAndSubjectHybrid(encryptedEmail[0], bobPrivateKeys);
    const emailDecryptedByAlice = await decryptEmailAndSubjectHybrid(encryptedEmail[1], alicePrivateKeys);

    expect(emailDecryptedByBob).toStrictEqual(emailDecryptedByAlice);
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

    await expect(
      encryptEmailAndSubjectHybridForMultipleRecipients(emailAndSubject, [bobWithPublicKeys, badEveWithPublicKeys]),
    ).rejects.toThrow(EmailHybridEncryptionError);
  });

  it('should throw an error if no recipients are provided', async () => {
    await expect(encryptEmailHybridForMultipleRecipients(email, [])).rejects.toThrow(InvalidInputEmail);

    await expect(
      encryptEmailHybridForMultipleRecipients(email, undefined as unknown as RecipientWithPublicKey[]),
    ).rejects.toThrow(InvalidInputEmail);

    await expect(encryptEmailAndSubjectHybridForMultipleRecipients(emailAndSubject, [])).rejects.toThrow(
      InvalidInputEmail,
    );

    await expect(
      encryptEmailAndSubjectHybridForMultipleRecipients(
        emailAndSubject,
        undefined as unknown as RecipientWithPublicKey[],
      ),
    ).rejects.toThrow(InvalidInputEmail);
  });

  it('should throw an error if input is invalid', async () => {
    await expect(encryptEmailHybrid({} as EmailBody, bobWithPublicKeys)).rejects.toThrow(InvalidInputEmail);

    await expect(encryptEmailAndSubjectHybrid({} as EmailBodyAndSubject, bobWithPublicKeys)).rejects.toThrow(
      InvalidInputEmail,
    );

    await expect(
      encryptEmailHybridForMultipleRecipients({} as EmailBody, [bobWithPublicKeys, aliceWithPublicKeys]),
    ).rejects.toThrow(InvalidInputEmail);

    await expect(
      encryptEmailAndSubjectHybridForMultipleRecipients({} as EmailBodyAndSubject, [
        bobWithPublicKeys,
        aliceWithPublicKeys,
      ]),
    ).rejects.toThrow(InvalidInputEmail);

    await expect(decryptEmailHybrid({} as HybridEncryptedEmail, bobPrivateKeys)).rejects.toThrow(
      EmailHybridDecryptionError,
    );

    await expect(decryptEmailAndSubjectHybrid({} as HybridEncryptedEmailAndSubject, bobPrivateKeys)).rejects.toThrow(
      EmailHybridDecryptionError,
    );
  });

  it('should throw an error if encrypted email is modified', async () => {
    const encryptedEmail = await encryptEmailHybrid(emailAndSubject, bobWithPublicKeys);

    const modifiedCiphertext = encryptedEmail;
    modifiedCiphertext.encEmailBody.encText += 'modified ciphertext';
    await expect(decryptEmailHybrid(modifiedCiphertext, bobPrivateKeys)).rejects.toThrow(EmailSymmetricDecryptionError);

    const modifiedKey = encryptedEmail;
    modifiedKey.encryptedKey.encryptedKey += 'modified key';
    await expect(decryptEmailHybrid(modifiedCiphertext, bobPrivateKeys)).rejects.toThrow(EmailHybridDecryptionError);
  });

  it('should throw an error if encrypted email and subject are modified', async () => {
    const encryptedEmail = await encryptEmailAndSubjectHybrid(emailAndSubject, bobWithPublicKeys);

    const modifiedCiphertext = encryptedEmail;
    modifiedCiphertext.encEmailBody.encText += 'modified ciphertext';
    await expect(decryptEmailAndSubjectHybrid(modifiedCiphertext, bobPrivateKeys)).rejects.toThrow(
      EmailSymmetricDecryptionError,
    );

    const modifiedKey = encryptedEmail;
    modifiedKey.encryptedKey.encryptedKey += 'modified key';
    await expect(decryptEmailAndSubjectHybrid(modifiedCiphertext, bobPrivateKeys)).rejects.toThrow(
      EmailHybridDecryptionError,
    );
  });
});
