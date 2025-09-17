import { describe, expect, it } from 'vitest';
import { createPwdProtectedEmailAndSubject, decryptPwdProtectedEmailAndSubject } from '../../src/email-crypto';
import { EmailBody, Email, User, EmailPublicParameters } from '../../src/types';

describe('Test email crypto functions', () => {
  const emailBody: EmailBody = {
    text: 'Hi Bob, This is a test message. -Alice.',
  };

  const sharedSecret = 'test shared secret';
  const userAlice: User = {
    email: 'alice email',
    name: 'alice',
    id: '1',
  };

  const userBob: User = {
    email: 'bob email',
    name: 'bob',
    id: '2',
  };
  const emailParams: EmailPublicParameters = {
    labels: ['test label 1', 'test label2'],
    createdAt: '2023-06-14T08:11:22.000Z',
    subject: 'test subject',
    sender: userAlice,
    recipient: userBob,
    replyToEmailID: 2,
    id: 'test id',
  };

  const email = {
    body: emailBody,
    params: emailParams,
  };

  it('should encrypt and decrypt email sucessfully', async () => {
    const encryptedEmail = await createPwdProtectedEmailAndSubject(email, sharedSecret);
    const decryptedEmail = await decryptPwdProtectedEmailAndSubject(encryptedEmail, sharedSecret);
    expect(decryptedEmail).toStrictEqual(email);
    expect(encryptedEmail.params.subject).not.toBe(email.params.subject);
  });

  it('should throw an error if encryption fails', async () => {
    const bad_email = {
      params: emailParams,
    } as unknown as Email;
    await expect(createPwdProtectedEmailAndSubject(bad_email, sharedSecret)).rejects.toThrowError(
      /Failed to password-protect email/,
    );
  });

  it('should throw an error if a different secret used for decryption', async () => {
    const encryptedEmail = await createPwdProtectedEmailAndSubject(email, sharedSecret);
    const wrongSecret = 'different secret';
    await expect(decryptPwdProtectedEmailAndSubject(encryptedEmail, wrongSecret)).rejects.toThrowError(
      /Failed to decrypt password-protect email/,
    );
  });
});
