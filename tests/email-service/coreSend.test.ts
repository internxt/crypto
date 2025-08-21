import { describe, it, expect } from 'vitest';
import { sendEmail } from '../../src/email-service/coreSend';
import { User } from '../../src/utils/types';

describe('Check sending api', () => {
  it('Should throw an error if public key is invalid', async () => {
    const userAlice: User = { email: 'alice email', name: 'alice' };
    const userBob: User = { email: 'bob email', name: 'bob' };
    const subject = 'test email subject';
    const emailBody = 'mock enc text $mock enc key';

    await expect(sendEmail(subject, emailBody, userAlice, userBob)).rejects.toThrowError(/Could not send an email/);
  });
});
