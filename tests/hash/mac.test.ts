import { describe, expect, it } from 'vitest';
import { computeMac } from '../../src/hash';
import { keyedHashHex } from '../../src/hash';

describe('Test mac via blake3 test vectors', () => {
  it('keyed hash should work with blake 3 test vector', async () => {
    const key = new TextEncoder().encode('whats the Elvish word for friend');
    const data = new Uint8Array([0, 1, 2, 3, 4, 5, 6]);
    const mac = keyedHashHex(key, [data]);
    expect(mac).toEqual('af0a7ec382aedc0cfd626e49e7628bc7a353a4cb108855541a5651bf64fbb28a');
  });

  it('compute should work', async () => {
    const key = 'Srp6AzybbyludWuaVwGoHa1C2H0Qtv7JR0sKGLSWe8Ho8_q9hezfYD2RYb9IUrW999pH4VlABgDLse484zAapg';
    const data = [new TextEncoder().encode('test'), new TextEncoder().encode('this'), new TextEncoder().encode('mac')];
    const mac = computeMac(key, data);
    expect(mac).toEqual('69e61015d45f1d2e33e380952cada43dd293e45188bfee5e35635e6d12edd815');
  });
});
