import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  HybridEncryptedEmail,
  Email,
  EmailBody,
  User,
  PwdProtectedEmail,
  EmailPublicParameters,
} from '../../src/types';
import { encryptEmailHybrid, createPwdProtectedEmail, generateEmailKeys } from '../../src/email-crypto';
import { sendHybridEmail, sendPwdProtectedEmail } from '../../src/email-service/sendingService';
import emailjs from '@emailjs/browser';

vi.mock('@emailjs/browser', () => ({
  default: {
    init: vi.fn(),
    send: vi.fn(),
    sendForm: vi.fn(),
  },
}));

describe('Test sending email functions', async () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const userAlice: User = { email: 'alice email', name: 'alice', id: '1' };
  const userBob: User = { email: 'bob email', name: 'bob', id: '2' };

  const serviceId = 'test-service-id';
  const templateId = 'test-template-id';
  const emailServicePublicKey = 'test-public-key';

  const emailBody: EmailBody = {
    text: 'test body',
  };
  const emailParams: EmailPublicParameters = {
    createdAt: '2023-06-14T08:11:22.000Z',
    labels: ['test label 1', 'test label2'],
    sender: userAlice,
    subject: 'test subject',
    recipient: userBob,
    replyToEmailID: 1,
    id: '1',
  };

  const email: Email = {
    body: emailBody,
    params: emailParams,
  };

  const { privateKeys: alicePrivateKeys } = await generateEmailKeys();
  const { publicKeys: bobPublicKeys } = await generateEmailKeys();

  const mockPassword = 'mock pwd';

  const bobWithPublicKeys = {
    ...userBob,
    publicKeys: bobPublicKeys,
  };

  it('should sucessfully send hybrid email', async () => {
    const encEmail: HybridEncryptedEmail = await encryptEmailHybrid(email, bobWithPublicKeys, alicePrivateKeys);
    const spy = vi.spyOn(emailjs, 'send').mockResolvedValue({ status: 200, text: 'OK' });
    await sendHybridEmail(encEmail);
    expect(spy).toHaveBeenCalled();
    expect(spy).toHaveBeenCalledWith(
      serviceId,
      templateId,
      expect.objectContaining({
        from_email: userAlice.email,
        from_name: userAlice.name,
        to_email: userBob.email,
        to_name: userBob.name,
        email_subject: email.params.subject,
      }),
      emailServicePublicKey,
    );
  });

  it('should throw an error if recipient does not match expected one', async () => {
    const encEmail: HybridEncryptedEmail = await encryptEmailHybrid(email, bobWithPublicKeys, alicePrivateKeys);
    const wrongEmail = { ...encEmail, recipientID: 'wrong id' };
    await expect(sendHybridEmail(wrongEmail)).rejects.toThrow(
      /Failed to email to the recipient: Email is encrypted for another recipient/,
    );
  });

  it('should throw an error if cannot send hybrid email', async () => {
    const encEmail: HybridEncryptedEmail = await encryptEmailHybrid(email, bobWithPublicKeys, alicePrivateKeys);
    vi.spyOn(emailjs, 'send').mockRejectedValue({ status: 404, text: 'Mocked Error' });
    await expect(sendHybridEmail(encEmail)).rejects.toThrow(/Failed to email to the recipient/);
  });

  it('should sucessfully send password protected email', async () => {
    const encEmail: PwdProtectedEmail = await createPwdProtectedEmail(email, mockPassword);

    const spy = vi.spyOn(emailjs, 'send').mockResolvedValue({ status: 200, text: 'OK' });
    await sendPwdProtectedEmail(encEmail);

    expect(spy).toHaveBeenCalled();
    expect(spy).toHaveBeenCalledWith(
      serviceId,
      templateId,
      expect.objectContaining({
        from_email: userAlice.email,
        from_name: userAlice.name,
        to_email: userBob.email,
        to_name: userBob.name,
        email_subject: email.params.subject,
      }),
      emailServicePublicKey,
    );
  });

  it('should throw an error if cannot send password protected email', async () => {
    const encEmail: PwdProtectedEmail = await createPwdProtectedEmail(email, mockPassword);

    vi.spyOn(emailjs, 'send').mockRejectedValue({ status: 401, text: 'Mock Error' });

    await expect(sendPwdProtectedEmail(encEmail)).rejects.toThrow(/Failed to email to the recipient/);

    vi.spyOn(emailjs, 'send').mockRejectedValue(new Error('Mock Error'));
    await expect(sendPwdProtectedEmail(encEmail)).rejects.toThrow(/Failed to email to the recipient/);
  });
});
