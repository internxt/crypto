import MiniSearch from 'minisearch';
import { Email } from '../types';

const options = {
  fields: ['subject', 'sender', 'recipients', 'body'],
  storeFields: ['sender'],
};

/**
 * Creates a MiniSearch index based on a set of emails
 *
 * @param emails - The list of emails
 * @returns The MiniSearch index
 */
export function getMiniSearchIndices(emails: Email[]): MiniSearch {
  try {
    const miniSearch = new MiniSearch(options);

    miniSearch.addAll(emails);

    return miniSearch;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to generate search index: ${errorMessage}`);
  }
}

/**
 * Converts a MiniSearch index into Uint8Array
 *
 * @param miniSearch - The MiniSearch index
 * @returns The Uint8Array representation of the MiniSearch index
 */
export function searializeIndices(miniSearch: MiniSearch): Uint8Array {
  try {
    const serializedIndex = JSON.stringify(miniSearch.toJSON());
    const encoder = new TextEncoder();
    const uint8Array = encoder.encode(serializedIndex);

    return uint8Array;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to serialize search index: ${errorMessage}`);
  }
}

/**
 * Converts an Uint8Array array into a MiniSearch index
 *
 * @param miniSearch - The Uint8Array array representation of the MiniSearch index
 * @returns The resulting MiniSearch index
 */
export function desearializeIndices(uint8Array: Uint8Array) {
  try {
    const decoder = new TextDecoder();
    const jsonString = decoder.decode(uint8Array);
    const miniSearch = MiniSearch.loadJSON(jsonString, options);

    return miniSearch;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to deserialize search index: ${errorMessage}`);
  }
}
