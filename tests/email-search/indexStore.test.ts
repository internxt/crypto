import { describe, expect, it } from 'vitest';
import {
  desearializeIndices,
  getCurrentSearchIndex,
  searializeIndices,
  decryptCurrentSearchIndices,
  encryptCurrentSearchIndices,
} from '../../src/email-search';
import { Email, NONCE_LENGTH } from '../../src/utils';
import { genSymmetricCryptoKey } from '../../src/symmetric-crypto';

const alice = { email: 'alice@email.com', name: 'alice' };
const bob = { email: 'bob@email.com', name: 'bob' };
const eve = { email: 'eve@email.com', name: 'eve' };
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
    recipients: [bob],
    emailChainLength: 0,
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
    recipients: [alice, eve],
    emailChainLength: 3,
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
    recipients: [alice, bob],
    emailChainLength: 1,
  },
  {
    id: '4',
    subject: 'Zen and the Art of Archery',
    body: {
      text: 'At first sight it must seem...',
      date: '2021-01-30T04:15:36.000Z',
      labels: ['non-fiction', 'education'],
    },
    recipients: [alice, eve],
    sender: bob,
    emailChainLength: 5,
  },
];

describe('Test search index functions', () => {
  it('should sucesfully encrypt and decrypt current index', async () => {
    const indices = getCurrentSearchIndex(emails);
    const results_before = indices.search('zen art motorcycle');

    const message = searializeIndices(indices);
    const key = await genSymmetricCryptoKey();
    const repets = 0;
    const init_aux = 'initial aux';

    const { nonce, aux, encIndices } = await encryptCurrentSearchIndices(key, message, repets, init_aux);
    const result = await decryptCurrentSearchIndices(key, encIndices, aux);
    const decrypted_indices = desearializeIndices(result);
    const results_after = decrypted_indices.search('zen art motorcycle');

    expect(results_before).toStrictEqual(results_after);
    expect(aux).toBe(init_aux);
    expect(nonce).toBe(0);
  });

  it('should successfully wrap the nonce if repeats exceed the limit', async () => {
    const indices = getCurrentSearchIndex(emails);
    const results_before = indices.search('zen art motorcycle');

    const message = searializeIndices(indices);
    const key = await genSymmetricCryptoKey();
    const repets = Math.pow(2, NONCE_LENGTH * 8);
    const init_aux = 'initial aux';

    const { nonce, encIndices, aux } = await encryptCurrentSearchIndices(key, message, repets, init_aux);
    const result = await decryptCurrentSearchIndices(key, encIndices, aux);
    const decrypted_indices = desearializeIndices(result);
    const results_after = decrypted_indices.search('zen art motorcycle');

    expect(results_before).toStrictEqual(results_after);
    expect(aux).not.toBe(init_aux);
    expect(nonce).toBe(0);
  });
});
