import { Email, User } from '../../src/types';
import { emailToBinary } from '../../src/email-crypto';

const randomString = (length: number = 8): string =>
  Math.random()
    .toString(36)
    .substring(2, 2 + length);

const randomDate = (): string => new Date(Date.now() - Math.floor(Math.random() * 1e10)).toISOString();

const randomUser = (): User => ({
  id: randomString(6),
  name: `User_${randomString(4)}`,
  email: `${randomString(6)}@example.com`,
});

export const generateTestEmail = (): Email => {
  const sender = randomUser();
  const recipient = randomUser();

  return {
    body: {
      text: `This is a test email body: ${randomString(20)}`,
      ...(Math.random() > 0.5 ? { attachments: [`file_${randomString(4)}.txt`] } : {}),
    },
    params: {
      id: randomString(10),
      subject: `Test Subject ${randomString(6)}`,
      createdAt: randomDate(),
      sender,
      recipient,
      recipients: Math.random() > 0.5 ? [randomUser(), randomUser()] : undefined,
      replyToEmailID: Math.random() > 0.7 ? Math.floor(Math.random() * 1000) : undefined,
      labels: Math.random() > 0.5 ? ['inbox', 'test'] : undefined,
    },
  };
};

export const generateTestEmails = (count: number): Email[] => {
  return Array.from({ length: count }, () => generateTestEmail());
};

export function getAllEmailSize(emails: Email[]): number {
  return emails.reduce((total, email) => {
    return total + emailToBinary(email).byteLength;
  }, 0);
}

export function getEmailSize(email: Email): number {
  return emailToBinary(email).byteLength;
}
