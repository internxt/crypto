import { describe, it, expect } from 'vitest';
import { hexToUint8Array, base64ToUint8Array, uint8ArrayToHex, uint8ArrayToBase64 } from '../../src/utils/converters';

describe('arrayToHex', () => {
  it('converts a simple Uint8Array to hex and back', () => {
    const arr = new Uint8Array([0, 1, 2, 255]);
    const hex = uint8ArrayToHex(arr);
    const result = hexToUint8Array(hex);

    expect(hex).toBe('000102ff');
    expect(result).toStrictEqual(arr);
  });

  it('handles an empty array', () => {
    const arr = new Uint8Array([]);
    expect(uint8ArrayToHex(arr)).toBe('');
  });

  it('converts a simple Uint8Array to utf string', () => {
    const arr = new Uint8Array([0, 1, 2, 255]);
    const uint8str = uint8ArrayToBase64(arr);
    const result = base64ToUint8Array(uint8str);

    expect(uint8str).toBe('AAEC/w==');
    expect(result).toStrictEqual(arr);
  });
});
