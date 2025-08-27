import { describe, expect, it } from 'vitest';
import { desearializeIndices, getMiniSearchIndices, searializeIndices } from '../../src/email-search/core';
import { Email } from '../../src/types';
import MiniSearch from 'minisearch';
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

describe('Test dummy search functions', () => {
  it('should sucessfully generate search index', async () => {
    const indices = getMiniSearchIndices(emails);
    const results = indices.search('zen art motorcycle');
    const expectedResult = [
      {
        id: '2',
        match: {
          art: ['subject'],
          motorcycle: ['subject'],
          zen: ['subject'],
        },
        queryTerms: ['zen', 'art', 'motorcycle'],
        score: 9.926306505038868,
        sender: {
          email: 'bob@email.com',
          id: '2',
          name: 'bob',
        },
        terms: ['zen', 'art', 'motorcycle'],
      },
      {
        id: '4',
        match: {
          art: ['subject'],
          zen: ['subject'],
        },
        queryTerms: ['zen', 'art'],
        score: 3.7144222958250506,
        sender: {
          email: 'bob@email.com',
          name: 'bob',
          id: '2',
        },
        terms: ['zen', 'art'],
      },
    ];

    expect(results).toStrictEqual(expectedResult);
  });

  it('should sucessfully generate search index', async () => {
    const indices = getMiniSearchIndices(emails);
    const results = indices.search('zen art motorcycle');

    const uint8 = searializeIndices(indices);
    const deserialized_indices = desearializeIndices(uint8);
    const results_after = indices.search('zen art motorcycle');

    expect(deserialized_indices).instanceOf(MiniSearch);
    expect(results).toStrictEqual(results_after);
  });
});
