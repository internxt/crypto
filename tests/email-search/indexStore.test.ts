import { describe, expect, expectTypeOf, it } from 'vitest';
import { openDatabase, EncryptedSearchDB, encryptAndStoreManyEmail, getEmailCount } from '../../src/email-search';
import { Email } from '../../src/types';
import { IDBPDatabase } from 'idb';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';

const alice = { email: 'alice@email.com', name: 'alice', id: '1' };
const bob = { email: 'bob@email.com', name: 'bob', id: '2' };
const eve = { email: 'eve@email.com', name: 'eve', id: '3' };
const emails: Email[] = [
  {
    body: {
      text: 'Call me Ishmael. Some years ago...',
    },
    params: {
      id: '1',
      date: '2023-06-14T08:11:22.000Z',
      labels: ['fiction'],
      subject: 'Moby Dick',
      sender: alice,
      recipient: bob,
      replyToEmailID: 0,
    },
  },
  {
    body: {
      text: 'I can see by my watch...',
    },
    params: {
      id: '2',
      subject: 'Zen and the Art of Motorcycle Maintenance',
      date: '2022-09-07T21:47:55.000Z',
      labels: ['fiction', 'self-help'],
      sender: bob,
      recipient: alice,
      recipients: [alice, eve],
      replyToEmailID: 3,
    },
  },
  {
    body: {
      text: 'The sky above the port was...',
    },
    params: {
      id: '3',
      subject: 'Neuromancer',
      date: '2021-01-30T04:15:36.000Z',
      labels: ['fiction'],
      sender: eve,
      recipient: bob,
      recipients: [alice, bob],
      replyToEmailID: 1,
    },
  },
  {
    body: {
      text: 'At first sight it must seem...',
    },
    params: {
      id: '4',
      subject: 'Zen and the Art of Archery',
      date: '2021-01-30T04:15:36.000Z',
      labels: ['non-fiction', 'education'],
      recipient: eve,
      recipients: [alice, eve],
      sender: bob,
      replyToEmailID: 5,
    },
  },
];
describe('Test searchable database functions', () => {
  it('should sucesfully open the database', async () => {
    const userID = 'mock ID';
    const db = await openDatabase(userID);

    expectTypeOf(db).toEqualTypeOf<IDBPDatabase<EncryptedSearchDB>>();

    const key = await genSymmetricCryptoKey();

    await encryptAndStoreManyEmail(emails, key, db);

    const count = await getEmailCount(db);
    expect(count).toBe(4);
  });
});
