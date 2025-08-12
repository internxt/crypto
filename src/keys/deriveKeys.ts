import { blake3 } from "hash-wasm";
import {
  CONTEXT_LOGIN,
  AES_KEY_BIT_LENGTH,
  CONTEXT_KEYSTORE,
  CONTEXT_RECOVERY,
  CONTEXT_INDEX,
} from "../utils/constants";
import { Buffer } from "buffer";

export async function deriveBitsFromContext(
  context: string,
  baseKey: string | Uint8Array,
  bits: number,
): Promise<Uint8Array> {
  const context_key = await blake3(context);

  const result = await blake3(baseKey, bits, Buffer.from(context_key, "hex"));
  return new Uint8Array(Buffer.from(result, "hex"));
}

export function keyToHex(key: Uint8Array): string {
  return Buffer.from(key).toString("hex");
}

export async function getIdentityKeystoreKey(
  baseKey: string | Uint8Array,
): Promise<Uint8Array> {
  return deriveBitsFromContext(CONTEXT_LOGIN, baseKey, AES_KEY_BIT_LENGTH);
}

export async function getEncryptionKeystoreKey(
  baseKey: string | Uint8Array,
): Promise<Uint8Array> {
  return deriveBitsFromContext(CONTEXT_KEYSTORE, baseKey, AES_KEY_BIT_LENGTH);
}

export async function getIndexKey(
  baseKey: string | Uint8Array,
): Promise<Uint8Array> {
  return deriveBitsFromContext(CONTEXT_INDEX, baseKey, AES_KEY_BIT_LENGTH);
}

export async function getRecoveryKey(
  recoveryCodes: string | Uint8Array,
): Promise<Uint8Array> {
  return deriveBitsFromContext(
    CONTEXT_RECOVERY,
    recoveryCodes,
    AES_KEY_BIT_LENGTH,
  );
}
