import { describe, it, expect } from 'vitest';
import { sendEncryptedEmail } from '../../src/email/api';
import { User } from '../../src/utils/types';

describe('Check sending api', () => {
  it('Should throw an error if public key is invalid', async () => {
    const userAlice: User = { email: 'alice email', name: 'alice' };
    const userBob: User = { email: 'bob email', name: 'bob' };
    const subject = 'test email subject';
    const encryptedText = 'mock enc text';
    const encryptedKey = 'mock enc key';

    await expect(sendEncryptedEmail(subject, encryptedText, encryptedKey, userAlice, userBob)).rejects.toThrowError(
      /Could not send an email/,
    );
  });
});
