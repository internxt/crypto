import { describe, expect, it } from 'vitest';
import {
  decryptEmailHybrid,
  encryptEmailHybridForMultipleRecipients,
  generateEmailKeys,
  decryptEmailAndSubjectHybrid,
  encryptEmailAndSubjectHybridForMultipleRecipients,
  decryptEmailPreviewHybrid,
} from '../../src/email-crypto';

import {
  Email,
  HybridEncKey,
  EmailAndSubject,
  RecipientWithPublicKey,
  EmailAndSubjectEncrypted,
  EmailEncrypted,
} from '../../src/types';
import {
  EmailHybridDecryptionError,
  EmailHybridEncryptionError,
  EmailPreviewSymmetricDecryptionError,
  EmailSymmetricDecryptionError,
  InvalidInputEmail,
} from '../../src/email-crypto/errors';

describe('Test email crypto functions', async () => {
  const email: Email = {
    text: 'test email text',
    preview: 'Hi Bib,',
    attachmentsSessionKey: new Uint8Array([1, 2, 3, 4]),
  };

  const emailAndSubject: EmailAndSubject = {
    text: 'test email text',
    subject: 'test email subject',
    preview: 'Hi Bib,',
    attachmentsSessionKey: new Uint8Array([1, 2, 3, 4]),
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
    const { encryptedKeys, encEmail } = await encryptEmailHybridForMultipleRecipients(email, [bobWithPublicKeys]);
    const decryptedEmail = await decryptEmailHybrid(encEmail, encryptedKeys[0], bobPrivateKeys);

    expect(decryptedEmail).toStrictEqual(email);
  });

  it('should decrypt email preview sucessfully', async () => {
    const { encryptedKeys, encEmail } = await encryptEmailHybridForMultipleRecipients(email, [bobWithPublicKeys]);
    const { preview: decryptedPreview } = await decryptEmailPreviewHybrid(
      encEmail.encPreview,
      encryptedKeys[0],
      bobPrivateKeys,
    );

    expect(decryptedPreview).toStrictEqual(email.preview);
  });

  it('should encrypt and decrypt email and subject sucessfully', async () => {
    const { encryptedKeys, encEmail } = await encryptEmailAndSubjectHybridForMultipleRecipients(emailAndSubject, [
      bobWithPublicKeys,
    ]);

    expect(encEmail?.encSubject).not.toBe(emailAndSubject.subject);
    const decryptedEmail = await decryptEmailAndSubjectHybrid(encEmail, encryptedKeys[0], bobPrivateKeys);

    expect(decryptedEmail).toStrictEqual(emailAndSubject);
  });

  it('should throw an error if public key is given instead of the secret one', async () => {
    const badRecipient = {
      email: 'alice email',
      publicHybridKey: alicePrivateKeys,
    };

    await expect(encryptEmailAndSubjectHybridForMultipleRecipients(emailAndSubject, [badRecipient])).rejects.toThrow(
      EmailHybridEncryptionError,
    );
  });

  it('should throw an error if not intended recipient', async () => {
    const { encryptedKeys, encEmail } = await encryptEmailHybridForMultipleRecipients(email, [bobWithPublicKeys]);

    await expect(decryptEmailHybrid(encEmail, encryptedKeys[0], alicePrivateKeys)).rejects.toThrow(
      EmailHybridDecryptionError,
    );

    await expect(decryptEmailPreviewHybrid(encEmail.encPreview, encryptedKeys[0], alicePrivateKeys)).rejects.toThrow(
      EmailHybridDecryptionError,
    );
  });

  it('should throw an error if hybrid email decryption fails', async () => {
    const encKey: HybridEncKey = {
      hybridCiphertext: 'mock kyber ciphertext',
      encryptedKey: 'mock encrypted key',
      encryptedForEmail: 'mock recipient email',
    };
    const badEncryptedEmail: EmailEncrypted = {
      encText: 'mock encrypted text',
      encPreview: 'mock encryped preview',
      encAttachmentsSessionKey: 'mock encrypted attachement session key',
    };

    const badEncryptedEmailAndSubject: EmailAndSubjectEncrypted = {
      encText: 'mock encrypted text',
      encSubject: 'mock encrypted subject',
      encPreview: 'mock encryped preview',
      encAttachmentsSessionKey: 'mock encrypted attachement session key',
    };

    await expect(decryptEmailHybrid(badEncryptedEmail, encKey, bobPrivateKeys)).rejects.toThrow(
      EmailHybridDecryptionError,
    );

    await expect(decryptEmailAndSubjectHybrid(badEncryptedEmailAndSubject, encKey, bobPrivateKeys)).rejects.toThrow(
      EmailHybridDecryptionError,
    );

    await expect(decryptEmailPreviewHybrid(badEncryptedEmail.encPreview, encKey, bobPrivateKeys)).rejects.toThrow(
      EmailHybridDecryptionError,
    );
  });

  it('should encrypt email to multiple senders sucessfully', async () => {
    const { encryptedKeys } = await encryptEmailHybridForMultipleRecipients(email, [
      bobWithPublicKeys,
      aliceWithPublicKeys,
    ]);

    expect(encryptedKeys).toHaveLength(2);
  });

  it('should encrypt email and subject to multiple senders sucessfully', async () => {
    const { encEmail, encryptedKeys } = await encryptEmailAndSubjectHybridForMultipleRecipients(emailAndSubject, [
      bobWithPublicKeys,
      aliceWithPublicKeys,
    ]);

    expect(encryptedKeys).toHaveLength(2);

    const emailDecryptedByBob = await decryptEmailAndSubjectHybrid(encEmail, encryptedKeys[0], bobPrivateKeys);
    const emailDecryptedByAlice = await decryptEmailAndSubjectHybrid(encEmail, encryptedKeys[1], alicePrivateKeys);

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
    await expect(encryptEmailHybridForMultipleRecipients({} as Email, [bobWithPublicKeys])).rejects.toThrow(
      InvalidInputEmail,
    );

    await expect(
      encryptEmailAndSubjectHybridForMultipleRecipients({} as EmailAndSubject, [bobWithPublicKeys]),
    ).rejects.toThrow(InvalidInputEmail);

    await expect(
      encryptEmailHybridForMultipleRecipients({} as Email, [bobWithPublicKeys, aliceWithPublicKeys]),
    ).rejects.toThrow(InvalidInputEmail);

    await expect(
      encryptEmailAndSubjectHybridForMultipleRecipients({} as EmailAndSubject, [
        bobWithPublicKeys,
        aliceWithPublicKeys,
      ]),
    ).rejects.toThrow(InvalidInputEmail);

    const { encEmail, encryptedKeys } = await encryptEmailHybridForMultipleRecipients(emailAndSubject, [
      bobWithPublicKeys,
    ]);

    await expect(decryptEmailHybrid({} as EmailEncrypted, encryptedKeys[0], bobPrivateKeys)).rejects.toThrow(
      EmailSymmetricDecryptionError,
    );

    await expect(decryptEmailHybrid(encEmail, {} as HybridEncKey, bobPrivateKeys)).rejects.toThrow(
      EmailHybridDecryptionError,
    );

    await expect(decryptEmailPreviewHybrid('', encryptedKeys[0], bobPrivateKeys)).rejects.toThrow(
      EmailPreviewSymmetricDecryptionError,
    );

    await expect(
      decryptEmailAndSubjectHybrid({} as EmailAndSubjectEncrypted, encryptedKeys[0], bobPrivateKeys),
    ).rejects.toThrow(EmailSymmetricDecryptionError);
  });

  it('should throw an error if encrypted email is modified', async () => {
    const { encEmail, encryptedKeys } = await encryptEmailHybridForMultipleRecipients(emailAndSubject, [
      bobWithPublicKeys,
    ]);

     const modifiedCiphertext = { ...encEmail };
    modifiedCiphertext.encText += 'modified ciphertext';
    await expect(decryptEmailHybrid(modifiedCiphertext, encryptedKeys[0], bobPrivateKeys)).rejects.toThrow(
      EmailSymmetricDecryptionError,
    );

    const modifiedKey = { ...encryptedKeys[0] };
    modifiedKey.encryptedKey = modifiedKey.encryptedKey.slice(0, -4) + 'AAAA';
    await expect(decryptEmailHybrid(encEmail, modifiedKey, bobPrivateKeys)).rejects.toThrow(EmailHybridDecryptionError);
  });

  it('should throw an error if encrypted email and subject are modified', async () => {
    const { encEmail, encryptedKeys } = await encryptEmailAndSubjectHybridForMultipleRecipients(emailAndSubject, [
      bobWithPublicKeys,
    ]);

    const modifiedCiphertext = { ...encEmail };
    modifiedCiphertext.encText += 'modified ciphertext';
    await expect(decryptEmailAndSubjectHybrid(modifiedCiphertext, encryptedKeys[0], bobPrivateKeys)).rejects.toThrow(
      EmailSymmetricDecryptionError,
    );

    const modifiedKey = { ...encryptedKeys[0] };
    modifiedKey.encryptedKey = modifiedKey.encryptedKey.slice(0, -4) + 'AAAA';
    await expect(decryptEmailAndSubjectHybrid(encEmail, modifiedKey, bobPrivateKeys)).rejects.toThrow(
      EmailHybridDecryptionError,
    );
  });
});
