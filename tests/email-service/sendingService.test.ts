import { describe, expect, it, vi, beforeEach } from 'vitest';
import { HybridEncryptedEmail, Email, EmailBody, User, PwdProtectedEmail } from '../../src/types';
import {
  encryptEmailHybrid,
  encryptEmailHybridForMultipleRecipients,
  createPwdProtectedEmail,
  generateEmailKeys,
  usersToRecipients,
} from '../../src/email-crypto';
import {
  sendHybridEmail,
  sendHybridEmailToMultipleRecipients,
  sendPwdProtectedEmail,
  sendPwdProtectedEmailToMultipleRecipients,
} from '../../src/email-service/sendingService';
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
  const userEve: User = { email: 'eve email', name: 'eve', id: '3' };

  const serviceId = 'test-service-id';
  const templateId = 'test-template-id';
  const emailServicePublicKey = 'test-public-key';

  const emailBody: EmailBody = {
    text: 'test body',
    date: '2023-06-14T08:11:22.000Z',
    labels: ['test label 1', 'test label2'],
  };

  const { privateKeys: alicePrivateKeys } = await generateEmailKeys(userAlice);
  const { publicKeys: bobPublicKeys } = await generateEmailKeys(userBob);
  const { publicKeys: evePublicKeys } = await generateEmailKeys(userEve);

  const mockPassword = 'mock pwd';

  it('should sucessfully send hybrid email', async () => {
    const email: Email = {
      body: emailBody,
      sender: userAlice,
      subject: 'test subject',
      recipients: usersToRecipients([userBob]),
      id: '1',
      replyToEmailID: 1,
    };

    const encEmail: HybridEncryptedEmail = await encryptEmailHybrid(email, bobPublicKeys, alicePrivateKeys);

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
        email_subject: email.subject,
      }),
      emailServicePublicKey,
    );
  });

  it('should throw an error if cannot send hybrid email', async () => {
    const email: Email = {
      body: emailBody,
      sender: userAlice,
      subject: 'test subject',
      recipients: usersToRecipients([userBob]),
      id: '1',
      replyToEmailID: 1,
    };

    const encEmail: HybridEncryptedEmail = await encryptEmailHybrid(email, bobPublicKeys, alicePrivateKeys);

    vi.spyOn(emailjs, 'send').mockRejectedValue({ status: 404, text: 'Mocked Error' });

    await expect(sendHybridEmail(encEmail)).rejects.toThrow(/Failed to email to the recipient/);
  });

  it('should sucessfully send hybrid email to multiple recipients', async () => {
    const email: Email = {
      body: emailBody,
      sender: userAlice,
      subject: 'test subject',
      recipients: usersToRecipients([userBob, userEve]),
      id: '1',
      replyToEmailID: 1,
    };

    const encEmails: HybridEncryptedEmail[] = await encryptEmailHybridForMultipleRecipients(
      email,
      [bobPublicKeys, evePublicKeys],
      alicePrivateKeys,
    );

    const spy = vi.spyOn(emailjs, 'send').mockResolvedValue({ status: 200, text: 'OK' });
    await sendHybridEmailToMultipleRecipients(encEmails);

    expect(spy).toHaveBeenCalledTimes(2);
    expect(spy).toHaveBeenCalledWith(
      serviceId,
      templateId,
      expect.objectContaining({
        from_email: userAlice.email,
        from_name: userAlice.name,
        to_email: userBob.email,
        to_name: userBob.name,
        email_subject: email.subject,
      }),
      emailServicePublicKey,
    );

    expect(spy).toHaveBeenCalledWith(
      serviceId,
      templateId,
      expect.objectContaining({
        from_email: userAlice.email,
        from_name: userAlice.name,
        to_email: userEve.email,
        to_name: userEve.name,
        email_subject: email.subject,
      }),
      emailServicePublicKey,
    );
  });

  it('should sucessfully send hybrid email to multiple recipients', async () => {
    const email: Email = {
      body: emailBody,
      sender: userAlice,
      subject: 'test subject',
      recipients: usersToRecipients([userBob, userEve]),
      id: '1',
      replyToEmailID: 1,
    };

    const encEmails: HybridEncryptedEmail[] = await encryptEmailHybridForMultipleRecipients(
      email,
      [bobPublicKeys, evePublicKeys],
      alicePrivateKeys,
    );

    vi.spyOn(emailjs, 'send')
      .mockResolvedValueOnce({ status: 200, text: 'OK' })
      .mockRejectedValue({ status: 404, text: 'Mocked Error' });
    await expect(sendHybridEmailToMultipleRecipients(encEmails)).rejects.toThrow(
      /Failed to email to multiple recipients/,
    );
  });

  it('should sucessfully send password protected email', async () => {
    const email: Email = {
      body: emailBody,
      sender: userAlice,
      subject: 'test subject',
      recipients: usersToRecipients([userBob]),
      id: '1',
      replyToEmailID: 1,
    };

    const encEmail: PwdProtectedEmail = await createPwdProtectedEmail(email, mockPassword);

    const spy = vi.spyOn(emailjs, 'send').mockResolvedValue({ status: 200, text: 'OK' });
    await sendPwdProtectedEmail(encEmail, userBob);

    expect(spy).toHaveBeenCalled();
    expect(spy).toHaveBeenCalledWith(
      serviceId,
      templateId,
      expect.objectContaining({
        from_email: userAlice.email,
        from_name: userAlice.name,
        to_email: userBob.email,
        to_name: userBob.name,
        email_subject: email.subject,
      }),
      emailServicePublicKey,
    );
  });

  it('should throw an error if cannot send password protected email', async () => {
    const email: Email = {
      body: emailBody,
      sender: userAlice,
      subject: 'test subject',
      recipients: usersToRecipients([userBob]),
      id: '1',
      replyToEmailID: 1,
    };

    const encEmail: PwdProtectedEmail = await createPwdProtectedEmail(email, mockPassword);

    vi.spyOn(emailjs, 'send').mockRejectedValue({ status: 401, text: 'Mock Error' });

    await expect(sendPwdProtectedEmail(encEmail, userBob)).rejects.toThrow(/Failed to email to the recipient/);
  });

  it('should sucessfully send password protected email to multiple recipients', async () => {
    const email: Email = {
      body: emailBody,
      sender: userAlice,
      subject: 'test subject',
      recipients: usersToRecipients([userBob, userEve]),
      id: '1',
      replyToEmailID: 1,
    };

    const encEmail: PwdProtectedEmail = await createPwdProtectedEmail(email, mockPassword);

    const spy = vi.spyOn(emailjs, 'send').mockResolvedValue({ status: 200, text: 'OK' });
    await sendPwdProtectedEmailToMultipleRecipients(encEmail);

    expect(spy).toHaveBeenCalledTimes(2);
    expect(spy).toHaveBeenCalledWith(
      serviceId,
      templateId,
      expect.objectContaining({
        from_email: userAlice.email,
        from_name: userAlice.name,
        to_email: userBob.email,
        to_name: userBob.name,
        email_subject: email.subject,
      }),
      emailServicePublicKey,
    );

    expect(spy).toHaveBeenCalledWith(
      serviceId,
      templateId,
      expect.objectContaining({
        from_email: userAlice.email,
        from_name: userAlice.name,
        to_email: userEve.email,
        to_name: userEve.name,
        email_subject: email.subject,
      }),
      emailServicePublicKey,
    );
  });

  it('should throw error if cannot send password protected email to multiple recipients', async () => {
    const email: Email = {
      body: emailBody,
      sender: userAlice,
      subject: 'test subject',
      recipients: usersToRecipients([userBob, userEve]),
      id: '1',
      replyToEmailID: 1,
    };

    const encEmail: PwdProtectedEmail = await createPwdProtectedEmail(email, mockPassword);

    vi.spyOn(emailjs, 'send')
      .mockResolvedValueOnce({ status: 200, text: 'OK' })
      .mockRejectedValue({ status: 404, text: 'Mocked Error' });

    await expect(sendPwdProtectedEmailToMultipleRecipients(encEmail)).rejects.toThrow(
      /Failed to email to multiple recipients/,
    );
  });
});
