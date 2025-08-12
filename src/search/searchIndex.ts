import { encryptSymmetrically, decryptSymmetrically } from "../core/symmetric";
import { INDEX_KEYSTORE_TAG, NONCE_LENGTH } from "../utils/constants";

const MAX_INDEX_VALUE = Math.pow(2, NONCE_LENGTH * 8);

export async function encryptCurrentIndices(
  secretKey: CryptoKey,
  indices: Uint8Array,
  repeats: number,
  current_aux: string,
): Promise<{
  nonce: number;
  ciphertext: Uint8Array;
  iv: Uint8Array;
  aux: string;
}> {
  let aux = current_aux;
  let nonce = repeats;
  if (repeats >= MAX_INDEX_VALUE) {
    nonce = 0;
    aux = INDEX_KEYSTORE_TAG + new Date().toDateString();
  }
  const { ciphertext, iv } = await encryptSymmetrically(
    secretKey,
    repeats,
    indices,
    aux,
  );
  return { nonce, ciphertext, iv, aux };
}

export async function decryptCurrentIndices(
  secretKey: CryptoKey,
  iv: Uint8Array,
  encryptedIndices: Uint8Array,
  aux: string,
): Promise<Uint8Array> {
  return decryptSymmetrically(secretKey, iv, encryptedIndices, aux);
}
