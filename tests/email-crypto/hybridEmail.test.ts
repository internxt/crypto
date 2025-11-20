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
import { encryptSymmetrically, genSymmetricCryptoKey } from '../../src/symmetric-crypto';
import { generateID } from '../../src/utils';

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
    replyToEmailID: generateID(),
  };

  const email: Email = {
    id: generateID(),
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
    const encryptedEmail = await encryptEmailHybrid(email, bobWithPublicKeys, alicePrivateKeys);
    const decryptedEmail = await decryptEmailHybrid(encryptedEmail, alicePublicKeys, bobPrivateKeys);

    expect(decryptedEmail).toStrictEqual(email);
  });

  it('should throw an error if public key is given instead of the secret one', async () => {
    const keys = await generateEccKeys();
    const kyberKeys = generateKyberKeys();

    const bad_alicePrivateKey: PrivateKeys = {
      eccPrivateKey: keys.publicKey,
      kyberPrivateKey: kyberKeys.secretKey,
    };

    await expect(encryptEmailHybrid(email, bobWithPublicKeys, bad_alicePrivateKey)).rejects.toThrowError(
      /Failed to encrypt email with hybrid encryption/,
    );
  });

  it('should throw an error if hybrid email decryption fails', async () => {
    const key = await genSymmetricCryptoKey();
    const freeField = new Uint8Array([1, 2, 3, 4]);
    const emailCiphertext = await encryptSymmetrically(
      key,
      new Uint8Array([1, 2, 3]),
      new TextEncoder().encode('aux'),
      freeField,
    );
    const encKey: HybridEncKey = {
      kyberCiphertext: new Uint8Array([1, 2, 3]),
      encryptedKey: new Uint8Array([4, 5, 6, 7]),
    };
    const bad_encrypted_email: HybridEncryptedEmail = {
      encryptedKey: encKey,
      enc: emailCiphertext,
      recipientEmail: userBob.email,
      params: emailParams,
      id: generateID(),
    };

    await expect(decryptEmailHybrid(bad_encrypted_email, alicePublicKeys, bobPrivateKeys)).rejects.toThrowError(
      /Failed to decrypt email with hybrid encryption/,
    );
  });

  it('should encrypt email to multiple senders sucessfully', async () => {
    const eveKyberKeys = generateKyberKeys();
    const eveKeys = await generateEccKeys();

    const evePublicKeys: PublicKeys = {
      eccPublicKey: eveKeys.publicKey,
      kyberPublicKey: eveKyberKeys.publicKey,
    };

    const eveWithPublicKeys = {
      email: 'eve email',
      name: 'eve',
      publicKeys: evePublicKeys,
    };

    const encryptedEmail = await encryptEmailHybridForMultipleRecipients(
      email,
      [bobWithPublicKeys, eveWithPublicKeys],
      alicePrivateKeys,
    );

    expect(encryptedEmail.length).toBe(2);
    expect(encryptedEmail[0].enc).toBe(encryptedEmail[1].enc);
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
      publicKeys: bad_evePublicKeys,
    };
    await expect(
      encryptEmailHybridForMultipleRecipients(email, [bobWithPublicKeys, bad_eveWithPublicKeys], alicePrivateKeys),
    ).rejects.toThrowError(/Failed to encrypt email to multiple recipients with hybrid encryption/);
  });
});
