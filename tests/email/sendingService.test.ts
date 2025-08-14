import { describe, expect, it, vi } from 'vitest';
import { HybridEncryptedEmail, Email, EmailBody, User, PublicKeys } from '../../src/utils/types';
import { encryptEmailHybrid } from '../../src/email/hybridEncEmail';
import { generateEccKeys } from '../../src/asymmetric';
import { generateKyberKeys } from '../../src/post-quantum/kyber768';
import { sendHybridEmail } from '../../src/email/sendingService';
import emailjs from '@emailjs/browser';

vi.mock('@emailjs/browser', () => ({
  default: {
    init: vi.fn(),
    send: vi.fn(),
    sendForm: vi.fn(),
  },
}));

describe('Test sending email functions', () => {
  it('should sucessfully send hybrid email', async () => {
    const userAlice: User = { email: 'alice email', name: 'alice' };
    const userBob: User = { email: 'bob email', name: 'bob' };
    const emailBody: EmailBody = {
      text: 'test body',
      date: '2023-06-14T08:11:22.000Z',
      labels: ['test label 1', 'test label2'],
    };

    const email: Email = {
      body: emailBody,
      sender: userAlice,
      subject: 'test subject',
      recipients: [userBob],
      id: '1',
      emailChainLength: 1,
    };

    const bobKeys = await generateEccKeys();
    const bobKyberKeys = generateKyberKeys();

    const recipientPublicKeys: PublicKeys = {
      user: userBob,
      eccPublicKey: bobKeys.publicKey,
      kyberPublicKey: bobKyberKeys.publicKey,
    };
    const senderKeyPair = await generateEccKeys();

    const encEmail: HybridEncryptedEmail = await encryptEmailHybrid(
      recipientPublicKeys,
      senderKeyPair.privateKey,
      email,
    );

    const spy = vi.spyOn(emailjs, 'send').mockResolvedValue({ status: 200, text: 'OK' });
    await sendHybridEmail(encEmail);

    expect(spy).toHaveBeenCalled();

    const serviceId = 'test-service-id';
    const templateId = 'test-template-id';
    const publicKey = 'test-public-key';
    expect(spy).toHaveBeenCalledWith(
      serviceId,
      templateId,
      expect.objectContaining({
        from_email: userAlice.email,
        from_name: userAlice.name,
        to_email: userBob.email,
        to_name: userBob.name,
        encrypted_subject: email.subject,
      }),
      publicKey,
    );
  });
});
