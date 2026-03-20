import { describe, expect, it } from 'vitest';
import { EmailBody } from '../../src/types';
import { decryptEmailBody, encryptEmailBody } from '../../src/email-crypto/core';
import { generateUuid } from '../../src/utils';
import { genSymmetricKey } from '../../src/symmetric-crypto';

describe('Test email crypto functions', () => {
  const emailBody: EmailBody = {
    text: 'test body',
    subject: 'test subject',
  };

  const aux = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

  it('should generate email id', async () => {
    const result1 = generateUuid();
    const result2 = generateUuid();
    expect(result1).not.toEqual(result2);
    expect(result1).toHaveLength(36);
  });

  it('should encrypt and decrypt email', async () => {
    const { encEmailBody, encryptionKey } = await encryptEmailBody(emailBody, aux);
    const result = await decryptEmailBody(encEmailBody, encryptionKey, aux);
    expect(result).toEqual(emailBody);
  });

  it('should throw an error if decryption fails', async () => {
    const { encEmailBody, encryptionKey } = await encryptEmailBody(emailBody, aux);
    const bad_encryptionKey = await genSymmetricKey();
    await expect(decryptEmailBody(encEmailBody, bad_encryptionKey, aux)).rejects.toThrowError(
      /Failed to symmetrically decrypt email body/,
    );

    const bad_aux = new Uint8Array([4, 5, 6, 7, 8]);
    await expect(decryptEmailBody(encEmailBody, encryptionKey, bad_aux)).rejects.toThrowError(
      /Failed to symmetrically decrypt email body/,
    );
  });

  it('should throw an error if cannot encrypt', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const bad_email: any = {};
    bad_email.self = bad_email;
    await expect(encryptEmailBody(bad_email, aux)).rejects.toThrowError(/Failed to symmetrically encrypt email body/);
  });
});
