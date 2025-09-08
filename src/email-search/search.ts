import { Index, DefaultSearchResults } from 'flexsearch';
import type { IndexOptions } from 'flexsearch';
import { Email } from '../types';
import { MailCache } from './mailCache';

type ExtendedIndexOptions = IndexOptions & {
  minlength?: number;
  resolution?: number;
  optimize?: boolean;
  fastupdate?: boolean;
  cache?: boolean;
};

const SUBJECT_OPTIONS: ExtendedIndexOptions = {
  preset: 'match',
  tokenize: 'forward',
  resolution: 9,
  minlength: 2,
  optimize: true,
  fastupdate: true,
  cache: true,
};
const BODY_OPTIONS: ExtendedIndexOptions = {
  ...SUBJECT_OPTIONS,
  minlength: 3,
  resolution: 6,
};

const FROM_OPTIONS: ExtendedIndexOptions = {
  ...SUBJECT_OPTIONS,
  tokenize: 'strict',
  minlength: 1,
};

const TO_OPTIONS: ExtendedIndexOptions = {
  ...SUBJECT_OPTIONS,
  tokenize: 'strict',
  minlength: 1,
};
export interface EmailSearchResult {
  email: Email;
  score?: number;
}

export interface EmailSearchIndex {
  subjectIndex: Index;
  bodyIndex: Index;
  fromIndex: Index;
  toIndex: Index;
  isReady: boolean;
}

export const createSearchIndex = (): EmailSearchIndex => ({
  subjectIndex: new Index(SUBJECT_OPTIONS),
  bodyIndex: new Index(BODY_OPTIONS),
  fromIndex: new Index(FROM_OPTIONS),
  toIndex: new Index(TO_OPTIONS),
  isReady: false,
});

export const addEmailToSearchIndex = (email: Email, searchIndex: EmailSearchIndex): void => {
  const emailId = email.params.id;

  if (email.params.subject) {
    searchIndex.subjectIndex.add(emailId, email.params.subject);
  }

  if (email.body?.text) {
    searchIndex.bodyIndex.add(emailId, email.body.text);
  }

  if (email.params.sender) {
    const senderText = `${email.params.sender.name || ''} ${email.params.sender.email || ''}`.trim();
    searchIndex.fromIndex.add(emailId, senderText);
  }

  const recipientsList = email.params.recipients?.length ? email.params.recipients : [email.params.recipient];

  const recipientsText = recipientsList
    .map((recipient) => `${recipient.name || ''} ${recipient.email || ''}`.trim())
    .join(' ');
  searchIndex.toIndex.add(emailId, recipientsText);
};

export const removeEmailFromSearchIndex = (emailId: string, searchIndex: EmailSearchIndex): void => {
  searchIndex.subjectIndex.remove(emailId);
  searchIndex.bodyIndex.remove(emailId);
  searchIndex.fromIndex.remove(emailId);
  searchIndex.toIndex.remove(emailId);
};

export const buildSearchIndexFromCache = async (
  esCache: MailCache<Email>,
  searchIndex: EmailSearchIndex,
): Promise<void> => {
  searchIndex.isReady = false;

  let processed = 0;

  for (const email of esCache.esCache.values()) {
    addEmailToSearchIndex(email, searchIndex);
    processed++;

    // Yield control every 50 emails to avoid blocking UI
    if (processed % 50 === 0) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }

  searchIndex.isReady = true;
};

export interface SearchOptions {
  fields?: ('subject' | 'body' | 'from' | 'to')[];
  limit?: number;
  boost?: {
    subject?: number;
    body?: number;
    from?: number;
    to?: number;
  };
}

export const searchEmails = async (
  query: string,
  esCache: MailCache<Email>,
  searchIndex: EmailSearchIndex,
  options: SearchOptions = {},
): Promise<EmailSearchResult[]> => {
  if (!searchIndex.isReady || !query.trim()) {
    return [];
  }

  const {
    fields = ['subject', 'body', 'from', 'to'],
    limit = 50,
    boost = { subject: 3, body: 1, from: 2, to: 2 },
  } = options;

  const results = new Map<string, number>();

  // Search each field and combine results
  const searchPromises = fields.map(async (field) => {
    let fieldResults: DefaultSearchResults;

    switch (field) {
      case 'subject':
        fieldResults = await searchIndex.subjectIndex.searchAsync(query);
        break;
      case 'body':
        fieldResults = await searchIndex.bodyIndex.searchAsync(query);
        break;
      case 'from':
        fieldResults = await searchIndex.fromIndex.searchAsync(query);
        break;
      case 'to':
        fieldResults = await searchIndex.toIndex.searchAsync(query);
        break;
      default:
        return;
    }

    const fieldBoost = boost[field] || 1;

    fieldResults.forEach((emailId) => {
      const currentScore = results.get(String(emailId)) || 0;
      // FlexSearch doesn't return scores in simple mode, so we use field boost as base score
      results.set(String(emailId), currentScore + fieldBoost);
    });
  });

  await Promise.all(searchPromises);

  const emailResults: EmailSearchResult[] = [];

  for (const [emailId, score] of results) {
    const email = esCache.esCache.get(emailId);
    if (email) {
      emailResults.push({ email, score });
    }
  }
  emailResults.sort((a, b) => (b.score || 0) - (a.score || 0));
  return emailResults.slice(0, limit);
};
