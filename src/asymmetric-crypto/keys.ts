import { CURVE_NAME, ECC_ALGORITHM } from '../constants';

/**
 * Generates elliptic curve key pair
 *
 * @returns The generated key pair
 */
export async function generateEccKeys(): Promise<CryptoKeyPair> {
  try {
    return await crypto.subtle.generateKey(
      {
        name: ECC_ALGORITHM,
        namedCurve: CURVE_NAME,
      },
      true,
      ['deriveBits'],
    );
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to generate elliptic curve key pair: ${errorMessage}`);
  }
}

/**
 * Converts public CryptoKey into Uint8Array using SubjectPublicKeyInfo format (RFC 5280)
 *
 * @returns The Uint8Array representation of the public key
 */
export async function exportPublicKey(key: CryptoKey): Promise<Uint8Array> {
  try {
    const result = await crypto.subtle.exportKey('spki', key);
    return new Uint8Array(result);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to export public key: ${errorMessage}`);
  }
}

/**
 * Converts public key in SubjectPublicKeyInfo format (RFC 5280) to CryptoKey
 *
 * @returns The CryptoKey representation of the public key
 */
export async function importPublicKey(spkiKeyData: Uint8Array): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey(
      'spki',
      spkiKeyData,
      {
        name: ECC_ALGORITHM,
        namedCurve: CURVE_NAME,
      },
      true,
      [],
    );
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to import public key: ${errorMessage}`);
  }
}

/**
 * Converts private key in CryptoKey to PKCS #8 format (RFC 5208)
 *
 * @returns The Uint8Array representation of the private key
 */
export async function exportPrivateKey(key: CryptoKey): Promise<Uint8Array> {
  try {
    const result = await crypto.subtle.exportKey('pkcs8', key);
    return new Uint8Array(result);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to export private key: ${errorMessage}`);
  }
}

/**
 * Converts private key in PKCS #8 format (RFC 5208) to CryptoKey
 *
 * @returns The CryptoKey representation of the private key
 */
export async function importPrivateKey(pkcs8KeyData: Uint8Array): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey(
      'pkcs8',
      pkcs8KeyData,
      {
        name: ECC_ALGORITHM,
        namedCurve: CURVE_NAME,
      },
      true,
      ['deriveBits'],
    );
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to import private key: ${errorMessage}`);
  }
}
