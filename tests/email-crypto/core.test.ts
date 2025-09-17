import { describe, expect, it } from 'vitest';
import { EmailBody, User, EmailPublicParameters } from '../../src/types';
import { decryptEmailSymmetrically, encryptEmailContentSymmetrically } from '../../src/email-crypto/core';
import { generateEmailID, getAux, getAuxWithoutSubject } from '../../src/email-crypto';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';

describe('Test email crypto functions', () => {
  const emailBody: EmailBody = {
    text: 'test body',
  };

  const userAlice: User = {
    email: 'alice email',
    name: 'alice',
    id: '1',
  };

  const userBob = {
    email: 'bob email',
    name: 'bob',
    id: '2',
  };

  const emailParams: EmailPublicParameters = {
    id: 'test id',
    labels: ['test label 1', 'test label2'],
    createdAt: '2023-06-14T08:11:22.000Z',
    subject: 'test subject',
    sender: userAlice,
    recipient: userBob,
    replyToEmailID: 2,
  };

  const aux = getAux(emailParams);

  it('should generate email id', async () => {
    const result1 = await generateEmailID();
    const result2 = await generateEmailID();
    expect(result1).not.toEqual(result2);
    expect(result1).toHaveLength(36);
  });

  it('should encrypt and decrypt email', async () => {
    const { enc, encryptionKey } = await encryptEmailContentSymmetrically(emailBody, aux, emailParams.id);
    const result = await decryptEmailSymmetrically(enc, encryptionKey, aux);
    expect(result).toEqual(emailBody);
  });

  it('should throw an error if decryption fails', async () => {
    const { enc, encryptionKey } = await encryptEmailContentSymmetrically(emailBody, aux, emailParams.id);
    const bad_encryptionKey = await genSymmetricCryptoKey();
    await expect(decryptEmailSymmetrically(enc, bad_encryptionKey, aux)).rejects.toThrowError(
      /Failed to symmetrically decrypt email/,
    );

    const bad_aux = 'bad aux string';
    await expect(decryptEmailSymmetrically(enc, encryptionKey, bad_aux)).rejects.toThrowError(
      /Failed to symmetrically decrypt email/,
    );
  });

  it('should throw an error if cannot create aux', async () => {
    const bad_params = { replyToEmailID: BigInt(423) };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => getAux(bad_params as any as EmailPublicParameters)).toThrowError(/Failed to create aux/);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => getAuxWithoutSubject(bad_params as any as EmailPublicParameters)).toThrowError(/Failed to create aux/);
  });

  it('should throw an error if cannot encrypt', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const bad_email: any = {};
    bad_email.self = bad_email;
    await expect(encryptEmailContentSymmetrically(bad_email, aux, emailParams.id)).rejects.toThrowError(
      /Failed to symmetrically encrypt email/,
    );
  });
});
