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
