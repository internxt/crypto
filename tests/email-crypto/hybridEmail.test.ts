import { describe, expect, it } from 'vitest';
import {
  encryptEmailHybrid,
  decryptEmailHybrid,
  encryptEmailHybridForMultipleRecipients,
  generateEmailKeys,
  usersToRecipients,
} from '../../src/email-crypto';

import { generateKyberKeys } from '../../src/post-quantum-crypto/kyber768';
import { generateEccKeys } from '../../src/asymmetric-crypto';
import { EmailBody, PublicKeys, Email, HybridEncryptedEmail, HybridEncKey, PrivateKeys } from '../../src/types';
import { encryptSymmetrically, genSymmetricCryptoKey } from '../../src/symmetric-crypto';

describe('Test email crypto functions', async () => {
  const emailBody: EmailBody = {
    text: 'test body',
    date: '2023-06-14T08:11:22.000Z',
    labels: ['test label 1', 'test label2'],
  };

  const userAlice = {
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

  const { privateKeys: alicePrivateKeys, publicKeys: alicePublicKeys } = await generateEmailKeys(userAlice);
  const { privateKeys: bobPrivateKeys, publicKeys: bobPublicKeys } = await generateEmailKeys(userBob);

  it('should encrypt and decrypt email sucessfully', async () => {
    const encryptedEmail = await encryptEmailHybrid(email, bobPublicKeys, alicePrivateKeys);
    const decryptedEmail = await decryptEmailHybrid(encryptedEmail, alicePublicKeys, bobPrivateKeys);

    expect(decryptedEmail).toStrictEqual(emailBody);
  });

  it('should throw an error if public key is given instead of the secret one', async () => {
    const keys = await generateEccKeys();
    const kyberKeys = generateKyberKeys();

    const bad_alicePrivateKey: PrivateKeys = {
      eccPrivateKey: keys.publicKey,
      kyberPrivateKey: kyberKeys.secretKey,
    };

    await expect(encryptEmailHybrid(email, bobPublicKeys, bad_alicePrivateKey)).rejects.toThrowError(
      /Failed to encrypt email with hybrid encryption/,
    );
  });

  it('should throw an error if hybrid email decryption fails', async () => {
    const key = await genSymmetricCryptoKey();

    const emailCiphertext = await encryptSymmetrically(key, new Uint8Array([1, 2, 3]), 'aux', 'userID');
    const encKey: HybridEncKey = {
      kyberCiphertext: new Uint8Array([1, 2, 3]),
      encryptedKey: new Uint8Array([4, 5, 6, 7]),
    };
    const bad_encrypted_email: HybridEncryptedEmail = {
      encryptedKey: encKey,
      ciphertext: emailCiphertext,
      subject: 'test subject',
      sender: userAlice,
      encryptedFor: userBob.id,
      recipients: usersToRecipients([userBob]),
      replyToEmailID: 2,
    };

    await expect(decryptEmailHybrid(bad_encrypted_email, alicePublicKeys, bobPrivateKeys)).rejects.toThrowError(
      /Failed to decrypt emails with hybrid encryption/,
    );
  });

  it('should encrypt email to multiple senders sucessfully', async () => {
    const userEve = {
      email: 'bob email',
      name: 'bob',
      id: '3',
    };

    const eveKyberKeys = generateKyberKeys();
    const eveKeys = await generateEccKeys();

    const evePublicKeys: PublicKeys = {
      userID: userEve.id,
      eccPublicKey: eveKeys.publicKey,
      kyberPublicKey: eveKyberKeys.publicKey,
    };

    const encryptedEmail = await encryptEmailHybridForMultipleRecipients(
      email,
      [bobPublicKeys, evePublicKeys],
      alicePrivateKeys,
    );

    expect(encryptedEmail.length).toBe(2);
    expect(encryptedEmail[0].ciphertext).toBe(encryptedEmail[1].ciphertext);
  });

  it('should throw an error if encryption to multiple recipients fails', async () => {
    const userEve = {
      email: 'eve email',
      name: 'eve',
      id: '3',
    };

    const eveKyberKeys = generateKyberKeys();
    const eveKeys = await generateEccKeys();

    const bad_evePublicKeys: PublicKeys = {
      userID: userEve.id,
      eccPublicKey: eveKeys.privateKey,
      kyberPublicKey: eveKyberKeys.publicKey,
    };
    await expect(
      encryptEmailHybridForMultipleRecipients(email, [bobPublicKeys, bad_evePublicKeys], alicePrivateKeys),
    ).rejects.toThrowError(/Failed to encrypt email to multiple recipients with hybrid encryption/);
  });
});
