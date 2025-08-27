import { Email, SearchIndices } from '../types';
import { searializeIndices, getMiniSearchIndices } from './core';

/**
 * Creates a search index based on a set of emails
 *
 * @param emails - The list of emails
 * @param userID - The user ID
 * @returns The current search index
 */
export function getCurrentSearchIndex(emails: Email[], userID: string): SearchIndices {
  try {
    const rawIndices = getMiniSearchIndices(emails);
    const data = searializeIndices(rawIndices);
    const result: SearchIndices = {
      data,
      userID,
      timestamp: new Date(),
    };

    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to get current search indices: ${errorMessage}`);
  }
}
