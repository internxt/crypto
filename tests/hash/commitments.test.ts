import { describe, expect, it } from 'vitest';
import { comitToMediaKey } from '../../src/hash';
import { MediaKeys } from '../../src/types';

describe('Test getHash with blake3 test vectors', () => {
  it('should generate different commitment if index is different', async () => {
    const key: MediaKeys = {
      userID: 'mock id',
      index: 1,
      pqKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
      olmKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
    };
    const commitment1 = await comitToMediaKey(key);
    key.index = 2;
    const commitment2 = await comitToMediaKey(key);
    expect(commitment1).not.toBe(commitment2);
  });

  it('should throw an error if cannot convert', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const invalidKeys: any = null;
    await expect(comitToMediaKey(invalidKeys)).rejects.toThrowError(/Failed to compute commitment to media keys/);
  });
});
