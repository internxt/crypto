import { describe, expect, it } from 'vitest';
import { ratchetMediaKey } from '../../src/derive-key';
import { MediaKeys } from '../../src/types';

describe('Test key ratchet', () => {
  it('should ratchet key', async () => {
    const key: MediaKeys = {
      olmKey: new Uint8Array([1, 2, 3, 4]),
      pqKey: new Uint8Array([1, 2, 3, 4]),
      index: 0,
      userID: 'id',
    };
    const result = await ratchetMediaKey(key);
    expect(result.index).toBe(1);
    expect(result.userID).toBe(key.userID);
    expect(result.olmKey.length).toBe(32);
    expect(result.pqKey.length).toBe(32);
  });

  it('should throw an error if ratchet fails', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const badKey = null as any;
    await expect(ratchetMediaKey(badKey)).rejects.toThrow(/Failed to ratchet media key/);
  });
});
