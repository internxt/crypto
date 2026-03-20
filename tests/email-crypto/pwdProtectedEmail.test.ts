import { describe, expect, it } from 'vitest';
import { createPwdProtectedEmail, decryptPwdProtectedEmail } from '../../src/email-crypto';
import { EmailBody } from '../../src/types';

describe('Test email crypto functions', () => {
  const email: EmailBody = {
    text: 'Hi Bob, This is a test message. -Alice.',
    subject: 'test subject',
  };

  const sharedSecret = 'test shared secret';

  it('should encrypt and decrypt email sucessfully', async () => {
    const encryptedEmail = await createPwdProtectedEmail(email, sharedSecret);
    const decryptedEmail = await decryptPwdProtectedEmail(encryptedEmail, sharedSecret);
    expect(decryptedEmail).toStrictEqual(email);
  });

  it('should throw an error if encryption fails', async () => {
    const badEmail = {} as unknown as EmailBody;
    await expect(createPwdProtectedEmail(badEmail, sharedSecret)).rejects.toThrowError(
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
