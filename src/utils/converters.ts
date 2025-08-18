import { Buffer } from 'buffer';

/**
 * Converts a Uint8Array into a hexadecimal string.
 *
 * @param array - The Uint8Array to convert.
 * @returns The hexadecimal string representation of the array.
 */
export function uint8ArrayToHex(array: Uint8Array): string {
  return Buffer.from(array).toString('hex');
}

/**
 * Converts a hexadecimal string into a Uint8Array.
 *
 * @param hex - The hexadecimal string to convert.
 * @returns A Uint8Array created from the hex string.
 */
export function hexToUint8Array(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

/**
 * Converts a Uint8Array into a base64 string.
 *
 * @param array - The Uint8Array to convert.
 * @returns The base64 string representation of the array.
 */
export function uint8ArrayToBase64(array: Uint8Array): string {
  return Buffer.from(array).toString('base64');
}

/**
 * Converts a base64 string into a Uint8Array.
 *
 * @param str - The base64 string to convert.
 * @returns A Uint8Array created from the base64 string.
 */
export function base64ToUint8Array(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, 'base64'));
}
