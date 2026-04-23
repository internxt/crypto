import { describe, expect, it } from 'vitest';
import {
  deriveSymmetricKeyFromTwoKeys,
  deriveSymmetricKeyFromContext,
  deriveDatabaseKey,
  deriveEmailDraftKey,
} from '../../src/derive-key';
import { uint8ArrayToHex, genMnemonic } from '../../src/utils';
import { AES_KEY_BYTE_LENGTH } from '../../src/constants';
import { genSymmetricKey } from '../../src/symmetric-crypto';

describe('Test derive key', () => {
  function createTestInput(size: number): Uint8Array {
    const result = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      result[i] = i % 251;
    }
    return result;
  }
  it('should derive symmetric key from two keys', async () => {
    const context = 'BLAKE3 2019-12-27 16:29:52 test vectors context';
    const input = createTestInput(63);
    const blake3TestResult = 'b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3';
    const result = deriveSymmetricKeyFromContext(context, input);
    const resultHex = uint8ArrayToHex(result);
    expect(resultHex).toBe(blake3TestResult);
  });

  it('should derive symmetric key from two keys', async () => {
    const key1 = genSymmetricKey();
    const key2 = genSymmetricKey();
    const key = await deriveSymmetricKeyFromTwoKeys(key1, key2);
    expect(key.length).toBe(AES_KEY_BYTE_LENGTH);
  });

  it('derive symmetric key from two keys should fail for small key', async () => {
    const shortKey = new Uint8Array([1, 2, 3]);
    const key2 = genSymmetricKey();
    expect(() => deriveSymmetricKeyFromTwoKeys(shortKey, key2)).toThrowError(
      /Failed to derive symmetric key from two keys/,
    );
    expect(() => deriveSymmetricKeyFromTwoKeys(key2, shortKey)).toThrowError(
      /Failed to derive symmetric key from two keys/,
    );
  });

  it('should derive symmetric key for database encryption', async () => {
    const mnemonic = genMnemonic();
    const key = await deriveDatabaseKey(mnemonic);
    expect(key.length).toBe(AES_KEY_BYTE_LENGTH);
    const key2 = await deriveDatabaseKey(mnemonic);
    expect(key2).toStrictEqual(key);
  });

  it('should derive symmetric key for email draft encryption', async () => {
    const mnemonic = genMnemonic();
    const key = await deriveEmailDraftKey(mnemonic);
    expect(key.length).toBe(AES_KEY_BYTE_LENGTH);
    const key2 = await deriveEmailDraftKey(mnemonic);
    expect(key2).toStrictEqual(key);
  });

  it('should derive symmetric key for email draft encryption', async () => {
    const mnemonic = genMnemonic();
    const keyDatabase = await deriveDatabaseKey(mnemonic);
    const keyDraft = await deriveEmailDraftKey(mnemonic);
    expect(keyDatabase.length).toBe(keyDraft.length);
    expect(keyDraft).not.toStrictEqual(keyDatabase);
  });
});
