import { Buffer } from 'buffer';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

/**
 * Generates a mnemonic of required bit strength
 *
 * @param bits - The bit strength.
 * @returns The generated mnemonic.
 */
export function genMnemonic(bits: number): string {
  return bip39.generateMnemonic(wordlist, bits);
}

/**
 * Decodes base64 string into UTF-8 string
 *
 * @param base64 - The base64 string.
 * @returns The UTF-8 string created from the base64 string.
 */
export function decodeBase64(base64: string): string {
  return Buffer.from(base64, 'base64').toString('utf-8');
}

/**
 * Encodes an UTF-8 string into base64 string
 *
 * @param str - The UTF-8 string.
 * @returns The base64 string created from the UTF-8 string.
 */
export function encodeBase64(str: string): string {
  return Buffer.from(str).toString('base64');
}

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
 * Converts a UTF-8 string into a Uint8Array.
 *
 * @param str - The UTF-8 string to convert.
 * @returns A Uint8Array created from the UTF-8 string.
 */
export function UTF8ToUint8(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, 'utf8'));
}

/**
 * Converts an Uint8Array into a UTF-8 string.
 *
 * @param array - The Uint8Array to convert.
 * @returns The UTF-8 string representation of the array.
 */
export function uint8ToUTF8(array: Uint8Array): string {
  return Buffer.from(array).toString('utf8');
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
