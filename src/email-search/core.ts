import MiniSearch from 'minisearch';
import { Email } from '../utils';

const options = {
  fields: ['subject', 'sender', 'recipients', 'body'],
  storeFields: ['sender'],
};

export function getMiniSearchIndices(emails: Email[]) {
  try {
    const miniSearch = new MiniSearch(options);

    miniSearch.addAll(emails);

    return miniSearch;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to generate search index: ${errorMessage}`);
  }
}

export function searializeIndices(miniSearch: MiniSearch) {
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
