import { describe, expect, it } from 'vitest';
import { EmailBody } from '../../src/types';
import { emailBodyToBinary, binaryToEmailBody } from '../../src/email-crypto';
describe('Test email crypto functions', () => {
  it('email converter to binary and back works', async () => {
    const email: EmailBody = {
      text: 'test body',
      attachments: ['test attachement 1', 'test attachement 2'],
    };
    const binary = emailBodyToBinary(email);
    const result = binaryToEmailBody(binary);
    expect(result).toEqual(email);
  });

  it('throws error if email converter to binary fails', async () => {
    const bad_binary: Uint8Array = new Uint8Array([
      49, 34, 44, 34, 116, 101, 115, 116, 32, 114, 101, 99, 105, 112, 105, 101, 110, 116, 32, 50, 34, 44, 34, 116, 101,
      115, 116, 32, 114, 101, 99, 105, 112, 105, 101, 110, 116, 32, 51, 34, 93, 44, 34,
    ]);
    expect(() => binaryToEmailBody(bad_binary)).toThrowError(/Failed to convert Uint8Array to EmailBody/);
  });

  it('throws error if binary to email converter fails', async () => {
    const bad_email = {
      id: BigInt(42),
      subject: 'test subject',
      body: 'test body',
      sender: 'test sender',
      recipient: ['test recipient 1', 'test recipient 2', 'test recipient 3'],
      createdAt: '2023-06-14T08:11:22.000Z',
      labels: ['test label 1', 'test label2'],
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => emailBodyToBinary(bad_email as any as EmailBody)).toThrowError(
      /Failed to convert EmailBody to Uint8Array/,
    );
  });
});
