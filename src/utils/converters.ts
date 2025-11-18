import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

/**
 * Converts a Uint8Array into a hexadecimal string.
 *
 * @param array - The Uint8Array to convert.
 * @returns The hexadecimal string representation of the array.
 */
export function uint8ArrayToHex(array: Uint8Array): string {
  return bytesToHex(array);
}

/**
 * Converts a UTF-8 string into a Uint8Array.
 *
 * @param str - The UTF-8 string to convert.
 * @returns A Uint8Array created from the UTF-8 string.
 */
export function UTF8ToUint8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Converts an Uint8Array into a UTF-8 string.
 *
 * @param array - The Uint8Array to convert.
 * @returns The UTF-8 string representation of the array.
 */
export function uint8ToUTF8(array: Uint8Array): string {
  return new TextDecoder().decode(array);
}

/**
 * Converts a hexadecimal string into a Uint8Array.
 *
 * @param hex - The hexadecimal string to convert.
 * @returns A Uint8Array created from the hex string.
 */
export function hexToUint8Array(hex: string): Uint8Array {
  return hexToBytes(hex);
}

/**
 * Converts a Uint8Array into a base64 string.
 *
 * @param array - The Uint8Array to convert.
 * @returns The base64 string representation of the array.
 */
export function uint8ArrayToBase64(buffer: Uint8Array): string {
  const array = Uint16Array.from(buffer);
  const binaryString = new TextDecoder('UTF-16').decode(array);
  return btoa(binaryString);
}

/**
 * Converts a base64 string into a Uint8Array.
 *
 * @param str - The base64 string to convert.
 * @returns A Uint8Array created from the base64 string.
 */
export function base64ToUint8Array(str: string): Uint8Array {
  const binaryString = atob(str);
  const len = binaryString.length;
  const array = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    array[i] = binaryString.charCodeAt(i);
  }
  return new Uint8Array(array.buffer);
}
