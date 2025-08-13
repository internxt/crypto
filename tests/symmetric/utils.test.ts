import { describe, expect, it } from 'vitest';
import { createIV } from '../../src/symmetric/utils';
import { IV_LENGTH, NONCE_LENGTH } from '../../src/utils/constants';

describe('Test symmetric functions', () => {
  it('should generate iv as expected', async () => {
    const n = 4;
    const iv = createIV(n);
    const view = new DataView(iv.buffer, 12, 4);
    const number = view.getUint32(0, false);

    expect(number).toBe(n);
    expect(iv.length).toBe(IV_LENGTH);

    const iv_new = createIV(n);
    expect(iv).not.toEqual(iv_new);
  });

  it('should handle the modules bigger than NONE_LENGTH', async () => {
    const n = 4;
    const max_value = Math.pow(2, NONCE_LENGTH * 8);
    const iv = createIV(n + max_value);
    const view = new DataView(iv.buffer, 12, 4);
    const number = view.getUint32(0, false);

    expect(number).toBe(n);
    expect(iv.length).toBe(IV_LENGTH);

    const iv_new = createIV(n);
    expect(iv).not.toEqual(iv_new);
  });
});
