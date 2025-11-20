import { describe, expect, it } from 'vitest';
import { EmailBody, User, EmailPublicParameters } from '../../src/types';
import {
  decryptEmailAndSubjectSymmetrically,
  decryptEmailSymmetrically,
  encryptEmailContentAndSubjectSymmetrically,
  encryptEmailContentSymmetrically,
} from '../../src/email-crypto/core';
import { generateID } from '../../src/utils';
import { getAux, getAuxWithoutSubject } from '../../src/email-crypto';
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
    replyToEmailID: generateID(),
  };

  const id = generateID();

  const aux = getAux(emailParams);

  it('should generate email id', async () => {
    const result1 = generateID();
    const result2 = generateID();
    expect(result1).not.toEqual(result2);
    expect(result1).toHaveLength(36);
  });

  it('should encrypt and decrypt email', async () => {
    const { enc, encryptionKey } = await encryptEmailContentSymmetrically(emailBody, aux, id);
    const result = await decryptEmailSymmetrically(enc, encryptionKey, aux);
    expect(result).toEqual(emailBody);
  });

  it('should throw an error if decryption fails', async () => {
    const { enc, encryptionKey } = await encryptEmailContentSymmetrically(emailBody, aux, id);
    const bad_encryptionKey = await genSymmetricCryptoKey();
    await expect(decryptEmailSymmetrically(enc, bad_encryptionKey, aux)).rejects.toThrowError(
      /Failed to symmetrically decrypt email/,
    );

    const {
      enc: encBody,
      encryptionKey: key,
      subjectEnc,
    } = await encryptEmailContentAndSubjectSymmetrically(emailBody, emailParams.subject, aux, id);
    await expect(decryptEmailAndSubjectSymmetrically(encBody, subjectEnc, bad_encryptionKey, aux)).rejects.toThrowError(
      /Failed to symmetrically decrypt email and subject/,
    );

    const bad_aux = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    await expect(decryptEmailSymmetrically(enc, encryptionKey, bad_aux)).rejects.toThrowError(
      /Failed to symmetrically decrypt email/,
    );

    await expect(decryptEmailAndSubjectSymmetrically(encBody, subjectEnc, key, bad_aux)).rejects.toThrowError(
      /Failed to symmetrically decrypt email and subject/,
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
    await expect(encryptEmailContentSymmetrically(bad_email, aux, id)).rejects.toThrowError(
      /Failed to symmetrically encrypt email/,
    );

    await expect(
      encryptEmailContentAndSubjectSymmetrically(bad_email, emailParams.subject, aux, id),
    ).rejects.toThrowError(/Failed to symmetrically encrypt email and subject/);
  });
});
