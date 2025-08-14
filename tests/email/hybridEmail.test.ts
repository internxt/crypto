import { describe, expect, it } from 'vitest';
import { encryptEmailHybrid, decryptEmailHybrid } from '../../src/email/hybridEncEmail';

import { generateKyberKeys } from '../../src/post-quantum/kyber768';
import { generateEccKeys } from '../../src/asymmetric';
import { EmailBody, PublicKeys, Email } from '../../src/utils/types';

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
});
