import { vi, it, describe, beforeEach, expect } from 'vitest';
import { createPwdProtectedEmail, createPwdProtectedEmailAndSubject, decryptPwdProtectedEmail, decryptPwdProtectedEmailAndSubject } from '../../src/email-crypto';
import { FailedToDecryptEmail, FailedToEncryptEmail } from '../../src/email-crypto/errors';
import { EmailBody, EmailBodyAndSubject, PwdProtectedEmail, PwdProtectedEmailAndSubject } from '../../src/types';
import * as core from '../../src/email-crypto/core';

vi.mock('../../src/email-crypto/core', async () => {
  const actual = await vi.importActual<typeof import('../../src/email-crypto/core')>(
    '../../src/email-crypto/core'
  );

  return {
    ...actual,
    passwordProtectKey: vi.fn(),
    removePasswordProtection: vi.fn(),
  };
});

describe('Test email crypto functions', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  const email: EmailBody = {
    text: 'Hi Bob, This is a test message. -Alice.',
    attachments: ['file1.txt', 'file2.txt'],
  };


  const emailAndSubject: EmailBodyAndSubject = {
    text: 'Hi Bob, This is a test message. -Alice.',
    attachments: ['file1.txt', 'file2.txt'],
    subject: 'test subject',
  };

  const sharedSecret = 'test shared secret';

it('throws FailedToEncryptEmail when encryption fails', async () => {
   const spy = vi.spyOn(core, 'passwordProtectKey');

  spy.mockRejectedValue(
    new Error('passwordProtectKey: unexpected failure'),
  );

  await expect(
    createPwdProtectedEmail(email, sharedSecret),
  ).rejects.toBeInstanceOf(FailedToEncryptEmail);

  await expect(
    createPwdProtectedEmailAndSubject(emailAndSubject, sharedSecret),
  ).rejects.toBeInstanceOf(FailedToEncryptEmail);
});

it('throws FailedToDecryptEmail when decryption fails', async () => {
  const encryptedEmail = {} as PwdProtectedEmail;
  const encryptedEmailAndSubject = {} as PwdProtectedEmailAndSubject;

  const spy = vi.spyOn(core, 'removePasswordProtection');

  spy.mockRejectedValue(
    new Error('removePasswordProtection: unexpected failure'),
  );
  
  await expect(
    decryptPwdProtectedEmail(encryptedEmail, sharedSecret),
  ).rejects.toBeInstanceOf(FailedToDecryptEmail);

  await expect(
    decryptPwdProtectedEmailAndSubject(encryptedEmailAndSubject, sharedSecret),
  ).rejects.toBeInstanceOf(FailedToDecryptEmail);
});

});