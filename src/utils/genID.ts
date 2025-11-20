import { v4 as uuidv4, parse, stringify } from 'uuid';
/**
 * Creates a random identifier.
 *
 * @returns The resulting auxilary string
 */
export function generateID(): string {
  return uuidv4();
}

export function uuidToBytes(uuid: string): Uint8Array {
  return parse(uuid);
}

export function bytesToUuid(bytes: Uint8Array): string {
  return stringify(bytes);
}
