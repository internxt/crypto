import { describe, expect, it } from 'vitest';
import { getCurrentSearchIndex } from '../../src/email-search';
import { Email } from '../../src/types';
import { usersToRecipients } from '../../src/email-crypto';

const alice = { email: 'alice@email.com', name: 'alice', id: '1' };
const bob = { email: 'bob@email.com', name: 'bob', id: '2' };
const eve = { email: 'eve@email.com', name: 'eve', id: '3' };
const emails: Email[] = [
  {
    id: '1',
    body: {
      text: 'Call me Ishmael. Some years ago...',
      date: '2023-06-14T08:11:22.000Z',
      labels: ['fiction'],
    },
    subject: 'Moby Dick',
    sender: alice,
    recipients: usersToRecipients([bob]),
    replyToEmailID: 0,
  },
  {
    id: '2',
    subject: 'Zen and the Art of Motorcycle Maintenance',
    body: {
      text: 'I can see by my watch...',
      date: '2022-09-07T21:47:55.000Z',
      labels: ['fiction', 'self-help'],
    },
    sender: bob,
    recipients: usersToRecipients([alice, eve]),
    replyToEmailID: 3,
  },
  {
    id: '3',
    subject: 'Neuromancer',
    body: {
      text: 'The sky above the port was...',
      date: '2021-01-30T04:15:36.000Z',
      labels: ['fiction'],
    },
    sender: eve,
    recipients: usersToRecipients([alice, bob]),
    replyToEmailID: 1,
  },
  {
    id: '4',
    subject: 'Zen and the Art of Archery',
    body: {
      text: 'At first sight it must seem...',
      date: '2021-01-30T04:15:36.000Z',
      labels: ['non-fiction', 'education'],
    },
    recipients: usersToRecipients([alice, eve]),
    sender: bob,
    replyToEmailID: 5,
  },
];

describe('Test search index functions', () => {
  it('should sucesfully encrypt and decrypt current index', async () => {
    const userID = 'mock ID';
    const indices = getCurrentSearchIndex(emails, userID);

    expect(indices.userID).toBe(userID);
    expect(indices.timestamp).instanceOf(Date);
  });
});
