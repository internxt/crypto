import { describe, it, expect } from 'vitest';
import { sendEmail } from '../../src/email-service/api-send';
import { User } from '../../src/types';

describe('Check sending api', () => {
  it('Should throw an error if public key is invalid', async () => {
    const userAlice: User = { email: 'alice email', name: 'alice', id: '1' };
    const userBob: User = { email: 'bob email', name: 'bob', id: '2' };
    const subject = 'test email subject';
    const emailBody = 'mock enc text $mock enc key';

    await expect(sendEmail(subject, emailBody, userAlice, userBob)).rejects.toThrowError(/Failed to send an email/);
  });
});
