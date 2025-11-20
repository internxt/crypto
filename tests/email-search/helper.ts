import { Email, User } from '../../src/types';
import { emailToBinary } from '../../src/email-crypto';
import { generateID } from '../../src/utils';

const randomString = (length: number = 8): string =>
  Math.random()
    .toString(36)
    .substring(2, 2 + length);

const randomDate = (): string => new Date(Date.now() - Math.floor(Math.random() * 1e10)).toISOString();

const randomUser = (): User => ({
  name: `User_${randomString(4)}`,
  email: `${randomString(6)}@example.com`,
});

export const generateTestEmail = (): Email => {
  const sender = randomUser();
  const recipient = randomUser();

  return {
    id: generateID(),
    body: {
      text: `This is a test email body: ${randomString(20)}`,
      ...(Math.random() > 0.5 ? { attachments: [`file_${randomString(4)}.txt`] } : {}),
    },
    params: {
      subject: `Test Subject ${randomString(6)}`,
      createdAt: randomDate(),
      sender,
      recipient,
      recipients: Math.random() > 0.5 ? [randomUser(), randomUser()] : undefined,
      replyToEmailID: generateID(),
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

export const generateEmailWithGivenText = (data: string): Email => {
  const sender = randomUser();
  const recipient = randomUser();

  return {
    id: generateID(),
    body: {
      text: data,
      ...(Math.random() > 0.5 ? { attachments: [`file_${randomString(4)}.txt`] } : {}),
    },
    params: {
      subject: `Test Subject ${randomString(6)}`,
      createdAt: randomDate(),
      sender,
      recipient,
      recipients: Math.random() > 0.5 ? [randomUser(), randomUser()] : undefined,
      replyToEmailID: generateID(),
      labels: Math.random() > 0.5 ? ['inbox', 'test'] : undefined,
    },
  };
};

export const getSearchTestEmails = (content: string[]): Email[] => {
  return content.map((text) => generateEmailWithGivenText(text));
};
