import { describe, it, expect } from 'vitest';
import { arrayToHex } from '../../src/utils/converters';
import { Buffer } from 'buffer';

describe('arrayToHex', () => {
  it('converts a simple Uint8Array to hex', () => {
    const arr = new Uint8Array([0, 1, 2, 255]);
    expect(arrayToHex(arr)).toBe('000102ff');
  });

  it('handles an empty array', () => {
    const arr = new Uint8Array([]);
    expect(arrayToHex(arr)).toBe('');
  });

  it('correctly formats single-byte values with leading zeros', () => {
    const arr = new Uint8Array([15, 16]);
    expect(arrayToHex(arr)).toBe('0f10');
  });

  it('works with large byte values', () => {
    const arr = new Uint8Array([254, 255]);
    expect(arrayToHex(arr)).toBe('feff');
  });

  it('is consistent with Buffer hex conversion', () => {
    const arr = new Uint8Array([10, 20, 30, 40]);
    expect(arrayToHex(arr)).toBe(Buffer.from(arr).toString('hex'));
  });
});
