import { describe, expect, it } from 'vitest';
import {
  encryptEmailHybrid,
  decryptEmailHybrid,
  encryptEmailHybridForMultipleRecipients,
  generateEmailKeys,
} from '../../src/email-crypto';

import { generateKyberKeys } from '../../src/post-quantum-crypto/kyber768';
import { generateEccKeys } from '../../src/asymmetric-crypto';
import {
  EmailBody,
  PublicKeys,
  HybridEncryptedEmail,
  HybridEncKey,
  PrivateKeys,
  EmailPublicParameters,
  Email,
} from '../../src/types';
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

  const { privateKeys: alicePrivateKeys, publicKeys: alicePublicKeys } = await generateEmailKeys();
  const { privateKeys: bobPrivateKeys, publicKeys: bobPublicKeys } = await generateEmailKeys();

  const bobWithPublicKeys = {
    ...userBob,
    publicKeys: bobPublicKeys,
  };

  it('should encrypt and decrypt email sucessfully', async () => {
    const encryptedEmail = await encryptEmailHybrid(email, bobWithPublicKeys, alicePrivateKeys, true);
    const decryptedEmail = await decryptEmailHybrid(encryptedEmail, alicePublicKeys, bobPrivateKeys);

    expect(decryptedEmail).toStrictEqual(email);
    expect(encryptedEmail.params.subject).not.toBe(email.params.subject);
  });

  it('should throw an error if public key is given instead of the secret one', async () => {
    const keys = await generateEccKeys();
    const kyberKeys = generateKyberKeys();

    const bad_alicePrivateKey: PrivateKeys = {
      eccPrivateKey: keys.publicKey,
      kyberPrivateKey: kyberKeys.secretKey,
    };

    await expect(encryptEmailHybrid(email, bobWithPublicKeys, bad_alicePrivateKey, true)).rejects.toThrowError(
      /Failed to encrypt email with hybrid encryption/,
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
        encText: 'mock encrypted email text',
      },
      recipientEmail: userBob.email,
      params: emailParams,
      id: 'test id',
      isSubjectEncrypted: true,
    };

    await expect(decryptEmailHybrid(bad_encrypted_email, alicePublicKeys, bobPrivateKeys)).rejects.toThrowError(
      /Failed to decrypt email with hybrid encryption/,
    );
  });

  it('should encrypt the email to multiple senders sucessfully', async () => {
    const { privateKeys: evePrivateKeys, publicKeys: evePublicKeys } = await generateEmailKeys();

    const eveWithPublicKeys = {
      email: 'eve email',
      name: 'eve',
      id: '3',
      publicKeys: evePublicKeys,
    };

    const encryptedEmail = await encryptEmailHybridForMultipleRecipients(
      email,
      [bobWithPublicKeys, eveWithPublicKeys],
      alicePrivateKeys,
      true,
    );

    expect(encryptedEmail.length).toBe(2);
    expect(encryptedEmail[0].enc).toBe(encryptedEmail[1].enc);
    expect(encryptedEmail[0].params.subject).toBe(encryptedEmail[1].params.subject);
    expect(encryptedEmail[0].params.subject).not.toBe(email.params.subject);

    const decEmailBob = await decryptEmailHybrid(encryptedEmail[0], alicePublicKeys, bobPrivateKeys);
    expect(decEmailBob).toStrictEqual(email);

    const decEmailEve = await decryptEmailHybrid(encryptedEmail[1], alicePublicKeys, evePrivateKeys);
    expect(decEmailEve).toStrictEqual(email);
  });

  it('should throw an error if encryption to multiple recipients fails', async () => {
    const eveKyberKeys = generateKyberKeys();
    const eveKeys = await generateEccKeys();

    const bad_evePublicKeys: PublicKeys = {
      eccPublicKey: eveKeys.privateKey,
      kyberPublicKey: eveKyberKeys.publicKey,
    };

    const bad_eveWithPublicKeys = {
      email: 'eve email',
      name: 'eve',
      id: '3',
      publicKeys: bad_evePublicKeys,
    };
    await expect(
      encryptEmailHybridForMultipleRecipients(
        email,
        [bobWithPublicKeys, bad_eveWithPublicKeys],
        alicePrivateKeys,
        true,
      ),
    ).rejects.toThrowError(/Failed to encrypt email to multiple recipients with hybrid encryption/);
  });
});
