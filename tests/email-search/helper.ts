import { Email, User } from '../../src/types';
import { emailToBinary } from '../../src/email-search/utils';
import { generateUuid } from '../../src/utils';

const randomString = (length: number = 8): string =>
  Math.random()
    .toString(36)
    .substring(2, 2 + length);

const randomDate = (): string => new Date(Date.now() - Math.floor(Math.random() * 1e10)).toISOString();

const randomUser = (): User => ({
  name: `User_${randomString(4)}`,
  email: `${randomString(6)}@example.com`,
});

export const generateTestEmail = (data?: string): Email => {
  const sender = randomUser();
  const recipient = randomUser();

  return {
    id: generateUuid(),
    body: {
      text: data ? data : `This is a test email body: ${randomString(20)}`,
      subject: `Test Subject ${randomString(6)}`,
      ...(Math.random() > 0.5 ? { attachments: [`file_${randomString(4)}.txt`] } : {}),
    },
    params: {
      createdAt: randomDate(),
      sender,
      recipient,
      recipients: Math.random() > 0.5 ? [randomUser(), randomUser()] : undefined,
      replyToEmailID: generateUuid(),
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

export const getSearchTestEmails = (content: string[]): Email[] => {
  return content.map((text) => generateTestEmail(text));
};
