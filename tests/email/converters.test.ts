import { describe, expect, it } from 'vitest';
import { EmailBody } from '../../src/utils/types';
import { emailToBinary, binaryToEmail } from '../../src/email/utils';

describe('Test email crypto functions', () => {
  it('converter to binary and back works', async () => {
    const email: EmailBody = {
      text: 'test body',
      date: '2023-06-14T08:11:22.000Z',
      labels: ['test label 1', 'test label2'],
    };
    const binary = emailToBinary(email);
    const result = binaryToEmail(binary);
    expect(result).toEqual(email);
  });

  it('throws error if binaryToEmail fails', async () => {
    const bad_binary: Uint8Array = new Uint8Array([
      49, 34, 44, 34, 116, 101, 115, 116, 32, 114, 101, 99, 105, 112, 105, 101, 110, 116, 32, 50, 34, 44, 34, 116, 101,
      115, 116, 32, 114, 101, 99, 105, 112, 105, 101, 110, 116, 32, 51, 34, 93, 44, 34,
    ]);
    expect(() => binaryToEmail(bad_binary)).toThrowError(/Cannot convert Uint8Array to email:/);
  });

  it('throws error if emailToBinary fails', async () => {
    const bad_email = {
      id: BigInt(42),
      subject: 'test subject',
      body: 'test body',
      sender: 'test sender',
      recipient: ['test recipient 1', 'test recipient 2', 'test recipient 3'],
      date: '2023-06-14T08:11:22.000Z',
      labels: ['test label 1', 'test label2'],
    };
    expect(() => emailToBinary(bad_email as any as EmailBody)).toThrowError(/Cannot convert email to Uint8Array:/);
  });
});
