import { Index, DefaultSearchResults } from 'flexsearch';
import type { IndexOptions } from 'flexsearch';
import { Email, MailCache, EmailSearchResult } from '../types';

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

export interface EmailSearchIndex {
  subjectIndex: Index;
  bodyIndex: Index;
  fromIndex: Index;
  toIndex: Index;
  isReady: boolean;
}

/**
 * Creates new email search index
 *
 * @returns The email search index
 */
const createSearchIndex = (): EmailSearchIndex => ({
  subjectIndex: new Index(SUBJECT_OPTIONS),
  bodyIndex: new Index(BODY_OPTIONS),
  fromIndex: new Index(FROM_OPTIONS),
  toIndex: new Index(TO_OPTIONS),
  isReady: false,
});

/**
 * Adds the given email to the email search index
 *
 * @param email - The email to add
 * @param searchIndex - The email search index
 */
export const addEmailToSearchIndex = (email: Email, searchIndex: EmailSearchIndex): void => {
  try {
    const emailId = email.id;

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
  } catch (error) {
    throw new Error('Failed to add email to the search index', { cause: error });
  }
};

/**
 * Removes the email from the email search index
 *
 * @param emailID - The email identifier
 * @param searchIndex - The email search index
 */
export const removeEmailFromSearchIndex = (emailID: string, searchIndex: EmailSearchIndex): void => {
  try {
    searchIndex.subjectIndex.remove(emailID);
    searchIndex.bodyIndex.remove(emailID);
    searchIndex.fromIndex.remove(emailID);
    searchIndex.toIndex.remove(emailID);
  } catch (error) {
    throw new Error(`Failed to remove email with ID ${emailID} from the search index`, { cause: error });
  }
};

/**
 * Buils the email search index from the email cache
 *
 * @param esCache - The email cache
 * @returns  The email search index
 */
export const buildSearchIndexFromCache = async (esCache: MailCache<Email>): Promise<EmailSearchIndex> => {
  try {
    const searchIndex = createSearchIndex();
    searchIndex.isReady = false;

    for (const email of esCache.esCache.values()) {
      addEmailToSearchIndex(email, searchIndex);
    }

    searchIndex.isReady = true;
    return searchIndex;
  } catch (error) {
    throw new Error('Failed build an email search index from the cache', { cause: error });
  }
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

/**
 * Searches in teh
 *
 * @param query - The string to search for
 * @param esCache - The email cache
 * @param searchIndex - The email search index
 * @param opetions - The optional search limitations
 * @returns The result of the email search (emails ans their corresponding result weights)
 */
export const searchEmails = async (
  query: string,
  esCache: MailCache<Email>,
  searchIndex: EmailSearchIndex,
  options: SearchOptions = {},
): Promise<EmailSearchResult[]> => {
  try {
    if (!searchIndex.isReady || !query.trim()) {
      return [];
    }

    const {
      fields = ['subject', 'body', 'from', 'to'],
      limit = 50,
      boost = { subject: 3, body: 1, from: 2, to: 2 },
    } = options;

    const results = new Map<string, number>();

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
  } catch (error) {
    throw new Error('Email search failed', { cause: error });
  }
};
