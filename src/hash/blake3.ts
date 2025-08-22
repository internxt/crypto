import { createBLAKE3 } from 'hash-wasm';

export async function getHash(len: number, data: string[] | Uint8Array[]) {
  try {
    const hasher = await createBLAKE3(len);
    hasher.init();
    for (const chunk of data) {
      hasher.update(chunk);
    }

    return hasher.digest('binary');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to compute hash: ${errorMessage}`);
  }
}

export async function getHashHex(len: number, data: string[] | Uint8Array[]) {
  try {
    const hasher = await createBLAKE3(len);
    hasher.init();
    for (const chunk of data) {
      hasher.update(chunk);
    }

    return hasher.digest();
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to email to compute hash: ${errorMessage}`);
  }
}
