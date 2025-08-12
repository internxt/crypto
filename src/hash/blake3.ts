import { createBLAKE3 } from 'hash-wasm';

export async function getHash(len: number, data: string[] | Uint8Array[]) {
  const hasher = await createBLAKE3(len);
  hasher.init();
  for (const chunk of data) {
    hasher.update(chunk);
  }

  return hasher.digest('binary');
}

export async function getHashHex(len: number, data: string[] | Uint8Array[]) {
  const hasher = await createBLAKE3(len);
  hasher.init();
  for (const chunk of data) {
    hasher.update(chunk);
  }

  return hasher.digest();
}
