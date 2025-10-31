import { describe, it, expect } from 'vitest';
import { EmailServiceAPI } from '../../src/email-service/api-send';
import { User, EmailPublicParameters } from '../../src/types';

describe('Check sending api', () => {
  const userAlice: User = { email: 'alice email', name: 'alice' };
  const userBob: User = { email: 'bob email', name: 'bob' };
  const subject = 'test email subject';
  const emailBody = 'mock enc text $mock enc key';

  const param: EmailPublicParameters = {
    createdAt: new Date().toDateString(),
    sender: userAlice,
    recipient: userBob,
    subject: subject,
  };

  it.skip('should send an email sucessfully', async () => {
    // These env variables should be set in the .env.test file
    const senderEmail = import.meta.env['VITE_EMAIL_SENDER'];
    const recipientEmail = import.meta.env['VITE_EMAIL_RECIPIENT'];
    const serverId = import.meta.env['VITE_SERVICE_ID'];
    const templateID = import.meta.env['VITE_TEMPLATE_ID'];
    const publicKey = import.meta.env['VITE_PUBLIC_KEY'];

    const senderService = new EmailServiceAPI(serverId, templateID, publicKey);
    const sender: User = { email: senderEmail, name: 'Mock Sender Name' };
    const recipient: User = { email: recipientEmail, name: 'Mock Recipient Name' };
    const subject = 'Mock  email subject';
    const emailBody = 'Mock encypted content for tests';
    const paramReam: EmailPublicParameters = {
      createdAt: new Date().toDateString(),
      sender,
      recipient,
      subject,
    };

    await expect(senderService.sendEmail(emailBody, paramReam)).resolves.toBeUndefined();
  });

  it('Should throw an error if public keys is invalid', async () => {
    const serverId = 'mock server id';
    const templateID = 'mock template id';
    const publicKey = 'invalid public key';

    const sender = new EmailServiceAPI(serverId, templateID, publicKey);
    await expect(sender.sendEmail(emailBody, param)).rejects.toThrowError(/Failed to send an email/);
  });
});
