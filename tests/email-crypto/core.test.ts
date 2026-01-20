import { describe, expect, it } from 'vitest';
import { EmailBody, User, EmailPublicParameters } from '../../src/types';
import {
  decryptEmailAndSubjectSymmetrically,
  decryptEmailSymmetrically,
  encryptEmailContentAndSubjectSymmetrically,
  encryptEmailContentSymmetrically,
} from '../../src/email-crypto/core';
import { generateUuid } from '../../src/utils';
import { getAux } from '../../src/email-crypto';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';

describe('Test email crypto functions', () => {
  const emailBody: EmailBody = {
    text: 'test body',
  };

  const userAlice: User = {
    email: 'alice email',
    name: 'alice',
  };

  const userBob = {
    email: 'bob email',
    name: 'bob',
  };

  const emailParams: EmailPublicParameters = {
    labels: ['test label 1', 'test label2'],
    createdAt: '2023-06-14T08:11:22.000Z',
    subject: 'test subject',
    sender: userAlice,
    recipient: userBob,
    replyToEmailID: generateUuid(),
  };

  const id = generateUuid();

  const aux = getAux(emailParams, false);

  it('should generate email id', async () => {
    const result1 = generateUuid();
    const result2 = generateUuid();
    expect(result1).not.toEqual(result2);
    expect(result1).toHaveLength(36);
  });

  it('should encrypt and decrypt email', async () => {
    const { enc, encryptionKey } = await encryptEmailContentSymmetrically(emailBody, aux, id);
    const result = await decryptEmailSymmetrically(encryptionKey, aux, enc);
    expect(result).toEqual(emailBody);
  });

  it('should throw an error if decryption fails', async () => {
    const { enc, encryptionKey } = await encryptEmailContentSymmetrically(emailBody, aux, id);
    const bad_encryptionKey = await genSymmetricCryptoKey();
    await expect(decryptEmailSymmetrically(bad_encryptionKey, aux, enc)).rejects.toThrowError(
      /Failed to symmetrically decrypt email/,
    );

    const bad_aux = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    await expect(decryptEmailSymmetrically(encryptionKey, bad_aux, enc)).rejects.toThrowError(
      /Failed to symmetrically decrypt email/,
    );
  });
  it('should throw an error if decryption fails', async () => {
    const bad_encryptionKey = await genSymmetricCryptoKey();
    const { enc, encryptionKey, encSubject } = await encryptEmailContentAndSubjectSymmetrically(
      emailBody,
      emailParams.subject,
      aux,
      id,
    );
    await expect(decryptEmailAndSubjectSymmetrically(bad_encryptionKey, aux, encSubject, enc)).rejects.toThrowError(
      /Failed to symmetrically decrypt email and subject/,
    );

    const bad_aux = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

    await expect(decryptEmailAndSubjectSymmetrically(encryptionKey, bad_aux, encSubject, enc)).rejects.toThrowError(
      /Failed to symmetrically decrypt email and subject/,
    );
  });

  it('should throw an error if cannot create aux', async () => {
    const bad_params = { replyToEmailID: BigInt(423) };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => getAux(bad_params as any as EmailPublicParameters, false)).toThrowError(/Failed to create aux/);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => getAux(bad_params as any as EmailPublicParameters, true)).toThrowError(/Failed to create aux/);
  });

  it('should throw an error if cannot encrypt', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const bad_email: any = {};
    bad_email.self = bad_email;
    await expect(encryptEmailContentSymmetrically(bad_email, aux, id)).rejects.toThrowError(
      /Failed to symmetrically encrypt email/,
    );

    await expect(
      encryptEmailContentAndSubjectSymmetrically(bad_email, emailParams.subject, aux, id),
    ).rejects.toThrowError(/Failed to symmetrically encrypt email and subject/);
  });
});
