import { describe, expect, it } from 'vitest';
import { encryptEmailHybrid, decryptEmailHybrid } from '../../src/email/hybridEncEmail';

import { generateKyberKeys } from '../../src/post-quantum/kyber768';
import { generateEccKeys } from '../../src/asymmetric/ecc';
import { Email } from '../../src/utils/types';

describe('Test email crypto functions', () => {
  it('should encrypt and decrypt email sucessfully', async () => {
    const email: Email = {
      id: '42',
      subject: 'Test subject',
      body: 'Hi Bob, This is a test message. -Alice.',
      sender: 'alice@example.com',
      recipient: ['bob@example.com'],
      date: '2025-03-4T08:11:22.000Z',
      labels: ['test label 1', 'test label2'],
    };
    const aliceKeys = await generateEccKeys();
    const bobKyberKeys = generateKyberKeys();
    const bobKeys = await generateEccKeys();

    const aux = 'Email from Alice to Bob';

    const encryptedEmail = await encryptEmailHybrid(
      bobKeys.publicKey,
      bobKyberKeys.publicKey,
      1,
      aliceKeys.privateKey,
      email,
      aux,
    );
    const decryptedEmail = await decryptEmailHybrid(
      aliceKeys.publicKey,
      bobKeys.privateKey,
      bobKyberKeys.secretKey,
      encryptedEmail,
      aux,
    );

    expect(decryptedEmail).toStrictEqual(email);
  });
});
