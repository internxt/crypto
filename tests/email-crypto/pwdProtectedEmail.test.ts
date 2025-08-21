import { describe, expect, it } from 'vitest';
import { createPwdProtectedEmail, decryptPwdProtectedEmail } from '../../src/email-crypto';
import { EmailBody, Email } from '../../src/utils';

describe('Test email crypto functions', () => {
  it('should encrypt and decrypt email sucessfully', async () => {
    const emailBody: EmailBody = {
      text: 'Hi Bob, This is a test message. -Alice.',
      date: '2025-03-4T08:11:22.000Z',
      labels: ['test label 1', 'test label2'],
    };

    const sharedSecret = 'test shared secret';
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
      body: emailBody,
      subject: 'test subject',
      sender: userAlice,
      recipients: [userBob],
      emailChainLength: 2,
    };

    const encryptedEmail = await createPwdProtectedEmail(email, sharedSecret);
    const decryptedEmail = await decryptPwdProtectedEmail(encryptedEmail, sharedSecret);
    expect(decryptedEmail).toStrictEqual(emailBody);
  });
});
