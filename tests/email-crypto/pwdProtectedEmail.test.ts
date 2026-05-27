import { describe, expect, it } from 'vitest';
import {
  createPwdProtectedEmail,
  createPwdProtectedEmailAndSubject,
  decryptPwdProtectedEmail,
  decryptPwdProtectedEmailAndSubject,
  EmailPasswordOpenError,
  EmailSymmetricDecryptionError,
  InvalidInputEmail,
} from '../../src/email-crypto';
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
    await expect(createPwdProtectedEmail({} as unknown as EmailBody, sharedSecret)).rejects.toThrow(InvalidInputEmail);
    await expect(createPwdProtectedEmailAndSubject({} as unknown as EmailBodyAndSubject, sharedSecret)).rejects.toThrow(
      InvalidInputEmail,
    );
  });

  it('should throw an error if a different secret used for decryption', async () => {
    const encryptedEmail = await createPwdProtectedEmail(email, sharedSecret);
    const wrongSecret = 'different secret';
    await expect(decryptPwdProtectedEmail(encryptedEmail, wrongSecret)).rejects.toThrow(EmailPasswordOpenError);

    const encryptedEmailAndSubject = await createPwdProtectedEmailAndSubject(emailAndSubject, sharedSecret);
    await expect(decryptPwdProtectedEmailAndSubject(encryptedEmailAndSubject, wrongSecret)).rejects.toThrow(
      EmailPasswordOpenError,
    );
  });

  it('should throw an error if password-protected email is modified', async () => {
    const encryptedEmail = await createPwdProtectedEmail(email, sharedSecret);

    const modifiedCiphertext = encryptedEmail;
    modifiedCiphertext.encEmailBody.encText += 'modified ciphertext';
    await expect(decryptPwdProtectedEmail(modifiedCiphertext, sharedSecret)).rejects.toThrow(
      EmailSymmetricDecryptionError,
    );
  });

  it('should throw an error if password-protected email and subject are modified', async () => {
    const encryptedEmail = await createPwdProtectedEmailAndSubject(emailAndSubject, sharedSecret);

    const modifiedCiphertext = encryptedEmail;
    modifiedCiphertext.encEmailBody.encText += 'modified ciphertext';
    await expect(decryptPwdProtectedEmailAndSubject(modifiedCiphertext, sharedSecret)).rejects.toThrow(
      EmailSymmetricDecryptionError,
    );
  });
});
