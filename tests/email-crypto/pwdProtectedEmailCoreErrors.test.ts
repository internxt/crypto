import { vi, it, describe, beforeEach, expect } from 'vitest';
import {
  createPwdProtectedEmail,
  createPwdProtectedEmailAndSubject,
  decryptPwdProtectedEmail,
  decryptPwdProtectedEmailAndSubject,
} from '../../src/email-crypto';
import { FailedToDecryptEmail, FailedToEncryptEmail } from '../../src/email-crypto/errors';
import { Email, EmailAndSubject, PwdProtectedEmail, PwdProtectedEmailAndSubject } from '../../src/types';
import * as core from '../../src/email-crypto/core';

vi.mock('../../src/email-crypto/core', async () => {
  const actual = await vi.importActual<typeof import('../../src/email-crypto/core')>('../../src/email-crypto/core');

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

  const email: Email = {
    text: 'Hi Bob, This is a test message. -Alice.',
    attachments: ['file1.txt', 'file2.txt'],
  };

  const emailAndSubject: EmailAndSubject = {
    text: 'Hi Bob, This is a test message. -Alice.',
    attachments: ['file1.txt', 'file2.txt'],
    subject: 'test subject',
  };

  const sharedSecret = 'test shared secret';

  it('throws FailedToEncryptEmail when encryption fails', async () => {
    const spy = vi.spyOn(core, 'passwordProtectKey');

    spy.mockRejectedValue(new Error('passwordProtectKey: unexpected failure'));

    await expect(createPwdProtectedEmail(email, sharedSecret)).rejects.toBeInstanceOf(FailedToEncryptEmail);

    await expect(createPwdProtectedEmailAndSubject(emailAndSubject, sharedSecret)).rejects.toBeInstanceOf(
      FailedToEncryptEmail,
    );
  });

      const encryptedEmail = {
  'encEmail': {
    'encText': 'Np2hSuNJinD6Z3KIiWhnH1qWBpaCed6dU2Du0JiDRxPLCJhMQ4FmQmqr5PRz3iHMWa7xWRRmsyeMyd1k8cwX4YRmVg==',
  },
  'encryptedKey': {
    'encryptedKey': 'PTSrN0aCrMoQIeSxQmmCHBhPFnJw8hx+Xu4nnbW81I+dvbyGAZmEvQ==',
    'salt': 'JUh7Xi0arXw/bhF4d+IEAw==',
  },
} as PwdProtectedEmail;
    const encryptedEmailAndSubject = {
  'encEmail': {
    'encSubject': '6LD/Cnv8/mCDSns53eZzPRyNa3d9gk+gdkiFhzIGouxlQMBeE6YkOA==',
    'encText': 'nH1NJoZnO1Trv7RQ4+3Z+/epqt422zjJIBPO6nzSFq2pDlLvgOUcrqMlCicn+fK74XP7gYeKfd6z1Qa517XyPsCvdQ==',
  },
  'encryptedKey': {
    'encryptedKey': 'ctMRiLHe5a3AxVIC8QdFOS7VXdVMrZOZsYuC5MUQ7jbzxQio75NN2g==',
    'salt': 'qWsXcWQlc/uo46b0c+if0A==',
  },
} as PwdProtectedEmailAndSubject;
  

  it('throws FailedToDecryptEmail when decryption fails', async () => {

    const spy = vi.spyOn(core, 'removePasswordProtection');

    spy.mockRejectedValue(new Error('removePasswordProtection: unexpected failure'));

    await expect(decryptPwdProtectedEmail(encryptedEmail, sharedSecret)).rejects.toBeInstanceOf(FailedToDecryptEmail);

    await expect(decryptPwdProtectedEmailAndSubject(encryptedEmailAndSubject, sharedSecret)).rejects.toBeInstanceOf(
      FailedToDecryptEmail,
    );
  });

  it('throws FailedToDecryptEmail when decryption fails with string error', async () => {

    const spy = vi.spyOn(core, 'removePasswordProtection');

    spy.mockRejectedValue('removePasswordProtection: unexpected failure');

    await expect(decryptPwdProtectedEmail(encryptedEmail, sharedSecret)).rejects.toBeInstanceOf(FailedToDecryptEmail);

    await expect(decryptPwdProtectedEmailAndSubject(encryptedEmailAndSubject, sharedSecret)).rejects.toBeInstanceOf(
      FailedToDecryptEmail,
    );
  });

  it('throws FailedToEncryptEmail when encryption fails with string error', async () => {
    const spy = vi.spyOn(core, 'passwordProtectKey');

    spy.mockRejectedValue('passwordProtectKey: unexpected failure');

    await expect(createPwdProtectedEmail(email, sharedSecret)).rejects.toBeInstanceOf(FailedToEncryptEmail);

    await expect(createPwdProtectedEmailAndSubject(emailAndSubject, sharedSecret)).rejects.toBeInstanceOf(
      FailedToEncryptEmail,
    );
  });
});
