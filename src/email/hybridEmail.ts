import { deriveEccBits } from '../core/ecc';
import { deriveWrappingKey, unwrapKey, wrapKey } from '../core/keyWrapper';
import {
  generateSymmetricKey,
  encryptSymmetrically,
  decryptSymmetrically,
} from '../core/symmetric';
import { encapsulateKyber, decapsulateKyber } from '../core/kyber';
import { Email, EncryptedEmailHybrid } from '../utils/types';
import { binaryToEmail, emailToBinary } from './converters';

export async function encryptEmailHybrid(
  recipientPublicKey: CryptoKey,
  recipientPublicKeyKyber: Uint8Array,
  emailsInChain: number,
  userPrivateKey: CryptoKey,
  email: Email,
  aux: string,
): Promise<EncryptedEmailHybrid> {
  const encryptionKey = await generateSymmetricKey();
  const binaryEmail = emailToBinary(email);
  const { ciphertext: encryptedEmail, iv } = await encryptSymmetrically(
    encryptionKey,
    emailsInChain,
    binaryEmail,
    aux,
  );

  const eccSecret = await deriveEccBits(recipientPublicKey, userPrivateKey);
  const { cipherText: kyberCiphertext, sharedSecret: kyberSecret } =
    encapsulateKyber(recipientPublicKeyKyber);
  const wrappingKey = await deriveWrappingKey(eccSecret, kyberSecret);

  const encryptedKey = await wrapKey(encryptionKey, wrappingKey);

  const result: EncryptedEmailHybrid = {
    encryptedEmail,
    kyberCiphertext,
    encryptedKey,
    iv,
  };

  return result;
}

export async function decryptEmailHybrid(
  senderPublicKey: CryptoKey,
  recipientPrivateKey: CryptoKey,
  recipientPrivateKeyKyber: Uint8Array,
  encryptedEmail: EncryptedEmailHybrid,
  aux: string,
) {
  const eccSecret = await deriveEccBits(senderPublicKey, recipientPrivateKey);
  const kyberSecret = decapsulateKyber(
    encryptedEmail.kyberCiphertext,
    recipientPrivateKeyKyber,
  );

  const wrappingKey = await deriveWrappingKey(eccSecret, kyberSecret);
  const encryptionKey = await unwrapKey(
    encryptedEmail.encryptedKey,
    wrappingKey,
  );
  const binaryEmail = await decryptSymmetrically(
    encryptionKey,
    encryptedEmail.iv,
    encryptedEmail.encryptedEmail,
    aux,
  );
  const email = binaryToEmail(binaryEmail);

  return email;
}
