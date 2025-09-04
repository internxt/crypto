import { describe, expect, it } from 'vitest';
import { createPwdProtectedEmail, decryptPwdProtectedEmail, getAux } from '../../src/email-crypto';
import { EmailBody, User, EmailPublicParameters } from '../../src/types';

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
    date: '2023-06-14T08:11:22.000Z',
    subject: 'test subject',
    sender: userAlice,
    recipient: userBob,
    replyToEmailID: 2,
    id: 'test id',
  };

  const aux = getAux(emailParams);
  it('should encrypt and decrypt email sucessfully', async () => {
    const encryptedEmail = await createPwdProtectedEmail(emailBody, sharedSecret, aux, emailParams.id);
    const decryptedEmail = await decryptPwdProtectedEmail(encryptedEmail, sharedSecret, aux);
    expect(decryptedEmail).toStrictEqual(emailBody);
  });

  it('should throw an error if a different secret used for decryption', async () => {
    const encryptedEmail = await createPwdProtectedEmail(emailBody, sharedSecret, aux, emailParams.id);
    const wrongSecret = 'different secret';
    await expect(decryptPwdProtectedEmail(encryptedEmail, wrongSecret, aux)).rejects.toThrowError(
      /Failed to decrypt password-protect email/,
    );
  });
});
