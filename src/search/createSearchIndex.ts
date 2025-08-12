import MiniSearch from 'minisearch';
import { Email } from '../utils/types';

const options = {
  fields: ['subject', 'sender', 'recipient', 'body'],
  storeFields: ['id'],
};

export function getCurrentIndex(emails: Email[]) {
  const miniSearch = new MiniSearch(options);

  miniSearch.addAll(emails);

  return miniSearch;
}

export function searializeIndices(miniSearch: MiniSearch) {
  const serializedIndex = JSON.stringify(miniSearch.toJSON());
  const encoder = new TextEncoder();
  const uint8Array = encoder.encode(serializedIndex);

  return uint8Array;
}

export function desearializeIndices(uint8Array: Uint8Array) {
  const decoder = new TextDecoder();
  const jsonString = decoder.decode(uint8Array);
  const miniSearch = MiniSearch.loadJSON(jsonString, options);

  return miniSearch;
}
