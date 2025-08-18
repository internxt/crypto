import { describe, expect, it } from 'vitest';
import {
  encryptEmailHybrid,
  decryptEmailHybrid,
  encryptEmailHybridForMultipleRecipients,
} from '../../src/email/hybridEncEmail';

import { generateKyberKeys } from '../../src/post-quantum/kyber768';
import { generateEccKeys } from '../../src/asymmetric';
import { EmailBody, PublicKeys, Email, HybridEncryptedEmail, HybridEncKey } from '../../src/utils/types';
import { encryptSymmetrically, genSymmetricCryptoKey } from '../../src/symmetric';

describe('Test email crypto functions', () => {
  it('should encrypt and decrypt email sucessfully', async () => {
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

    const aliceKeys = await generateEccKeys();
    const bobKyberKeys = generateKyberKeys();
    const bobKeys = await generateEccKeys();

    const bobPublicKeys: PublicKeys = {
      user: userBob,
      eccPublicKey: bobKeys.publicKey,
      kyberPublicKey: bobKyberKeys.publicKey,
    };
    const encryptedEmail = await encryptEmailHybrid(bobPublicKeys, aliceKeys.privateKey, email);
    const decryptedEmail = await decryptEmailHybrid(
      aliceKeys.publicKey,
      bobKeys.privateKey,
      bobKyberKeys.secretKey,
      encryptedEmail,
    );

    expect(decryptedEmail).toStrictEqual(emailBody);
  });

  it('should throw an error if hybrid email encryption fails', async () => {
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

    const aliceKeys = await generateEccKeys();
    const bobKyberKeys = generateKyberKeys();
    const bobKeys = await generateEccKeys();

    const bobPublicKeys: PublicKeys = {
      user: userBob,
      eccPublicKey: bobKeys.publicKey,
      kyberPublicKey: bobKyberKeys.publicKey,
    };

    await expect(encryptEmailHybrid(bobPublicKeys, aliceKeys.publicKey, email)).rejects.toThrowError(
      /Could not encrypt email with hybrid encryption/,
    );
  });

  it('should throw an error if hybrid email decryption fails', async () => {
    const userAlice = {
      email: 'alice email',
      name: 'alice',
    };

    const userBob = {
      email: 'bob email',
      name: 'bob',
    };

    const aliceKeys = await generateEccKeys();
    const bobKyberKeys = generateKyberKeys();
    const bobKeys = await generateEccKeys();
    const key = await genSymmetricCryptoKey();

    const emailCiphertext = await encryptSymmetrically(key, 42, new Uint8Array([1, 2, 3]), 'aux');
    const encKey: HybridEncKey = {
      kyberCiphertext: new Uint8Array([1, 2, 3]),
      encryptedKey: new Uint8Array([4, 5, 6, 7]),
    };
    const bad_encrypted_email: HybridEncryptedEmail = {
      encryptedKey: encKey,
      ciphertext: emailCiphertext,
      subject: 'test subject',
      sender: userAlice,
      encryptedFor: userBob,
      recipients: [userBob],
      emailChainLength: 2,
    };

    await expect(
      decryptEmailHybrid(aliceKeys.publicKey, bobKeys.privateKey, bobKyberKeys.secretKey, bad_encrypted_email),
    ).rejects.toThrowError(/Could not decrypt emails with hybrid encryption/);
  });

  it('should encrypt email to multiple senders sucessfully', async () => {
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

    const userEve = {
      email: 'bob email',
      name: 'bob',
    };

    const email: Email = {
      id: 'test id',
      subject: 'test subject',
      body: emailBody,
      sender: userAlice,
      recipients: [userBob, userEve],
      emailChainLength: 2,
    };

    const aliceKeys = await generateEccKeys();
    const bobKyberKeys = generateKyberKeys();
    const bobKeys = await generateEccKeys();
    const eveKyberKeys = generateKyberKeys();
    const eveKeys = await generateEccKeys();

    const bobPublicKeys: PublicKeys = {
      user: userBob,
      eccPublicKey: bobKeys.publicKey,
      kyberPublicKey: bobKyberKeys.publicKey,
    };

    const evePublicKeys: PublicKeys = {
      user: userEve,
      eccPublicKey: eveKeys.publicKey,
      kyberPublicKey: eveKyberKeys.publicKey,
    };
    const encryptedEmail = await encryptEmailHybridForMultipleRecipients(
      [bobPublicKeys, evePublicKeys],
      aliceKeys.privateKey,
      email,
    );

    expect(encryptedEmail.length).toBe(2);
    expect(encryptedEmail[0].ciphertext).toBe(encryptedEmail[1].ciphertext);
  });

  it('should throw an error if encryption to multiple recipients fails', async () => {
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

    const userEve = {
      email: 'bob email',
      name: 'bob',
    };

    const email: Email = {
      id: 'test id',
      subject: 'test subject',
      body: emailBody,
      sender: userAlice,
      recipients: [userBob, userEve],
      emailChainLength: 2,
    };

    const aliceKeys = await generateEccKeys();
    const bobKyberKeys = generateKyberKeys();
    const bobKeys = await generateEccKeys();
    const eveKyberKeys = generateKyberKeys();
    const eveKeys = await generateEccKeys();

    const bobPublicKeys: PublicKeys = {
      user: userBob,
      eccPublicKey: bobKeys.publicKey,
      kyberPublicKey: bobKyberKeys.publicKey,
    };

    const bad_evePublicKeys: PublicKeys = {
      user: userEve,
      eccPublicKey: eveKeys.privateKey,
      kyberPublicKey: eveKyberKeys.publicKey,
    };
    await expect(
      encryptEmailHybridForMultipleRecipients([bobPublicKeys, bad_evePublicKeys], aliceKeys.privateKey, email),
    ).rejects.toThrowError(/Could not encrypt email to multiple recipients with hybrid encryption/);
  });
});
