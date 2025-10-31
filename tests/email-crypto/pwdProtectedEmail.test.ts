import { describe, expect, it } from 'vitest';
import { createPwdProtectedEmail, decryptPwdProtectedEmail } from '../../src/email-crypto';
import { EmailBody, User, EmailPublicParameters, Email } from '../../src/types';

describe('Test email crypto functions', () => {
  const emailBody: EmailBody = {
    text: 'Hi Bob, This is a test message. -Alice.',
  };

  const sharedSecret = 'test shared secret';
  const userAlice: User = {
    email: 'alice email',
    name: 'alice',
  };

  const userBob: User = {
    email: 'bob email',
    name: 'bob',
  };
  const emailParams: EmailPublicParameters = {
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
    id: 'test id',
  };

  it('should encrypt and decrypt email sucessfully', async () => {
    const encryptedEmail = await createPwdProtectedEmail(email, sharedSecret);
    const decryptedEmail = await decryptPwdProtectedEmail(encryptedEmail, sharedSecret);
    expect(decryptedEmail).toStrictEqual(email);
  });

  it('should throw an error if encryption fails', async () => {
    const bad_email = {
      params: emailParams,
    } as unknown as Email;
    await expect(createPwdProtectedEmail(bad_email, sharedSecret)).rejects.toThrowError(
      /Failed to password-protect email/,
    );
  });

  it('should throw an error if a different secret used for decryption', async () => {
    const encryptedEmail = await createPwdProtectedEmail(email, sharedSecret);
    const wrongSecret = 'different secret';
    await expect(decryptPwdProtectedEmail(encryptedEmail, wrongSecret)).rejects.toThrowError(
      /Failed to decrypt password-protect email/,
    );
  });
});
