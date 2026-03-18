import { describe, expect, it } from 'vitest';
import {
  encryptEmailHybrid,
  decryptEmailHybrid,
  encryptEmailHybridForMultipleRecipients,
  generateEmailKeys,
} from '../../src/email-crypto';

import { EmailBody, HybridEncryptedEmail, HybridEncKey, EmailPublicParameters, Email } from '../../src/types';
import { generateUuid } from '../../src/utils';

describe('Test email crypto functions', async () => {
  const emailBody: EmailBody = {
    text: 'test body',
  };

  const userAlice = {
    email: 'alice email',
    name: 'alice',
  };

  const userBob = {
    email: 'bob email',
    name: 'bob',
  };

  const emailParams: EmailPublicParameters = {
    labels: ['test label 1', 'test label2'],
    createdAt: '2023-06-14T08:11:22.000Z',
    subject: 'test subject',
    sender: userAlice,
    recipient: userBob,
    replyToEmailID: generateUuid(),
  };

  const email: Email = {
    id: generateUuid(),
    body: emailBody,
    params: emailParams,
  };

  const { secretKey: alicePrivateKeys, publicKey: alicePublicKeys } = await generateEmailKeys();
  const { secretKey: bobPrivateKeys, publicKey: bobPublicKeys } = await generateEmailKeys();

  const bobWithPublicKeys = {
    ...userBob,
    publicHybridKey: bobPublicKeys,
  };
  const aliceWithPublicKeys = {
    ...userAlice,
    publicHybridKey: alicePublicKeys,
  };

  it('should encrypt and decrypt email sucessfully', async () => {
    const encryptedEmail = await encryptEmailHybrid(email, bobWithPublicKeys);
    const decryptedEmail = await decryptEmailHybrid(encryptedEmail, bobPrivateKeys);

    expect(decryptedEmail).toStrictEqual(email);
  });

  it('should throw an error if public key is given instead of the secret one', async () => {
    const bad_recipient = {
      ...userAlice,
      publicHybridKey: alicePrivateKeys,
    };

    await expect(encryptEmailHybrid(email, bad_recipient)).rejects.toThrowError(
      /Failed to encrypt email with hybrid encryption/,
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
      kyberCiphertext: 'mock kyber ciphertext',
      encryptedKey: 'mock encrypted key',
    };
    const bad_encrypted_email: HybridEncryptedEmail = {
      encryptedKey: encKey,
      enc: {
        encText: 'mock encrypted text',
      },
      recipientEmail: userBob.email,
      params: emailParams,
      id: generateUuid(),
      isSubjectEncrypted: false,
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
    expect(encryptedEmail[0].enc).toBe(encryptedEmail[1].enc);
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
