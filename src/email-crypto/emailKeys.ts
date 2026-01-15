import { generateEccKeys } from '../asymmetric-crypto';
import { generateKyberKeys } from '../post-quantum-crypto';
import { EmailKeys } from '../types';

/**
 * Generates public and private keys for email service.
 *
 * @returns The user's private and public keys
 */
export async function generateEmailKeys(): Promise<EmailKeys> {
  try {
    const kyberKeys = generateKyberKeys();
    const keys = await generateEccKeys();

    const emailKeys: EmailKeys = {
      publicKeys: {
        eccPublicKey: keys.publicKey,
        kyberPublicKey: kyberKeys.publicKey,
      },
      privateKeys: {
        eccPrivateKey: keys.privateKey,
        kyberPrivateKey: kyberKeys.secretKey,
      },
    };

    return emailKeys;
  } catch (error) {
    throw new Error('Failed to generate keys for email service', { cause: error });
  }
}
