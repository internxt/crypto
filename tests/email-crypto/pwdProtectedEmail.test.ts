import { describe, expect, it } from 'vitest';
import { createPwdProtectedEmail, createPwdProtectedEmailAndSubject, decryptPwdProtectedEmail, decryptPwdProtectedEmailAndSubject, EmailPasswordOpenError, InvalidInputEmail } from '../../src/email-crypto';
import { EmailBody, EmailBodyAndSubject } from '../../src/types';

describe('Test email crypto functions', () => {
  const email: EmailBody = {
    text: 'Hi Bob, This is a test message. -Alice.',
  };

   const emailAndSubject: EmailBodyAndSubject = {
    text: 'Hi Bob, This is a test message. -Alice.',
    subject: 'test subject',
  };

  const sharedSecret = 'test shared secret';

  it('should encrypt and decrypt email sucessfully', async () => {
    const encryptedEmail = await createPwdProtectedEmail(email, sharedSecret);
    const decryptedEmail = await decryptPwdProtectedEmail(encryptedEmail, sharedSecret);
    expect(decryptedEmail).toStrictEqual(email);
  });

   it('should encrypt and decrypt email and subjectsucessfully', async () => {
    const encryptedEmail = await createPwdProtectedEmailAndSubject(emailAndSubject, sharedSecret);
    const decryptedEmail = await decryptPwdProtectedEmailAndSubject(encryptedEmail, sharedSecret);
    expect(decryptedEmail).toStrictEqual(emailAndSubject);
  });

  it('should throw an error if encryption fails', async () => {
    const badEmail = {} as unknown as EmailBody;
    await expect(createPwdProtectedEmail(badEmail, sharedSecret)).rejects.toThrow(
     InvalidInputEmail
    );
  });

  it('should throw an error if a different secret used for decryption', async () => {
    const encryptedEmail = await createPwdProtectedEmail(email, sharedSecret);
    const wrongSecret = 'different secret';
    await expect(decryptPwdProtectedEmail(encryptedEmail, wrongSecret)).rejects.toThrow(
      EmailPasswordOpenError
    );
  });
});
