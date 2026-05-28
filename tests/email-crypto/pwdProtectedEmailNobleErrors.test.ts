import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createPwdProtectedEmail,
  createPwdProtectedEmailAndSubject,
  EmailPasswordProtectError,
  EmailSymmetricEncryptionError,
} from '../../src/email-crypto';
import { Email, EmailAndSubject } from '../../src/types';
import * as nobleUtils from '@noble/hashes/utils.js';
import * as nobleWrapper from '@noble/ciphers/aes.js';

// Noble is ESM module and doesn't work with spyOn directly (module namespace is not configurable in ESM), must be mocked before.
// To mock it but keep the original implementation for most tests, we use importActual.
// vi.resetAllMocks(); before each test is a must to reset the mock back to importActual.
vi.mock('@noble/hashes/utils.js', async () => {
  const actual = await vi.importActual<typeof import('@noble/hashes/utils.js')>('@noble/hashes/utils.js');

  return {
    ...actual,
    randomBytes: vi.fn(actual.randomBytes),
  };
});

vi.mock('@noble/ciphers/aes.js', async () => {
  const actual = await vi.importActual<typeof import('@noble/ciphers/aes.js')>('@noble/ciphers/aes.js');

  return {
    ...actual,
    aeskw: vi.fn(actual.aeskw),
  };
});

describe('Test email crypto functions', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  const email: Email = {
    text: 'Hi Bob, This is a test message. -Alice.',
  };

  const emailAndSubject: EmailAndSubject = {
    text: 'Hi Bob, This is a test message. -Alice.',
    subject: 'test subject',
  };

  const sharedSecret = 'test shared secret';

  it('throws EmailSymmetricEncryptionError when symmetric encryption fails', async () => {
    vi.spyOn(nobleUtils, 'randomBytes').mockImplementation(() => {
      throw new Error('randomBytes: unexpected crypto failure');
    });

    await expect(createPwdProtectedEmail(email, sharedSecret)).rejects.toThrow(EmailSymmetricEncryptionError);
    await expect(createPwdProtectedEmailAndSubject(emailAndSubject, sharedSecret)).rejects.toThrow(
      EmailSymmetricEncryptionError,
    );
  });

  it('throws EmailPasswordProtectError when key wrapping fails', async () => {
    vi.spyOn(nobleWrapper, 'aeskw').mockImplementation(() => {
      throw new Error('aeskw: unexpected crypto failure');
    });

    await expect(createPwdProtectedEmail(email, sharedSecret)).rejects.toThrow(EmailPasswordProtectError);
    await expect(createPwdProtectedEmailAndSubject(emailAndSubject, sharedSecret)).rejects.toThrow(
      EmailPasswordProtectError,
    );
  });
});
