import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { AES_KEY_BIT_LENGTH } from '../constants';
/**
 * Generates a mnemonic
 *
 * @returns The generated mnemonic.
 */
export function genMnemonic(): string {
  return bip39.generateMnemonic(wordlist, AES_KEY_BIT_LENGTH);
}

/**
 * Converts a mnemonic to Uint8Array
 *
 * @param mnemonic - The mnemonic to convert
 * @returns The mnemonic as Uint8Array
 */
export function mnemonicToBytes(mnemonic: string): Uint8Array {
  return bip39.mnemonicToEntropy(mnemonic, wordlist);
}

/**
 * Converts a Uint8Array to a mnemonic
 *
 * @param bytes - The bytes to convert
 * @returns The mnemonic string
 */
export function bytesToMnemonic(bytes: Uint8Array): string {
  return bip39.entropyToMnemonic(bytes, wordlist);
}
