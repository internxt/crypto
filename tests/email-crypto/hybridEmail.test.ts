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
} from '../../src/types';
import { encryptSymmetrically, genSymmetricCryptoKey } from '../../src/symmetric-crypto';

describe('Test email crypto functions', async () => {
  const emailBody: EmailBody = {
    text: 'test body',
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

  const emailParams: EmailPublicParameters = {
    id: 'test id',
    labels: ['test label 1', 'test label2'],
    createdAt: '2023-06-14T08:11:22.000Z',
    subject: 'test subject',
    sender: userAlice,
    recipient: userBob,
    replyToEmailID: 2,
  };

  const email = {
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

    const emailCiphertext = await encryptSymmetrically(key, new Uint8Array([1, 2, 3]), 'aux', 'userID');
    const encKey: HybridEncKey = {
      kyberCiphertext: new Uint8Array([1, 2, 3]),
      encryptedKey: new Uint8Array([4, 5, 6, 7]),
    };
    const bad_encrypted_email: HybridEncryptedEmail = {
      encryptedKey: encKey,
      enc: emailCiphertext,
      recipientID: '1',
      params: emailParams,
    };

    await expect(decryptEmailHybrid(bad_encrypted_email, alicePublicKeys, bobPrivateKeys)).rejects.toThrowError(
      /Failed to decrypt emails with hybrid encryption/,
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
      id: '3',
      publicKeys: evePublicKeys,
    };

    const encryptedEmail = await encryptEmailHybridForMultipleRecipients(
      email,
      [bobWithPublicKeys, eveWithPublicKeys],
      alicePrivateKeys,
    );

    expect(encryptedEmail.length).toBe(2);
    expect(encryptedEmail[0].enc.ciphertext).toBe(encryptedEmail[1].enc.ciphertext);
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
      encryptEmailHybridForMultipleRecipients(email, [bobWithPublicKeys, bad_eveWithPublicKeys], alicePrivateKeys),
    ).rejects.toThrowError(/Failed to encrypt email to multiple recipients with hybrid encryption/);
  });
});
