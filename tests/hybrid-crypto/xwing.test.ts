import { describe, expect, it } from 'vitest';
import { decapsulateHybrid, encapsulateHybrid, genHybridKeys } from '../../src/hybrid-crypto';
import {
  XWING_PUBLIC_KEY_LENGTH,
  XWING_SECRET_KEY_LENGTH,
  XWING_SEED_BYTE_LENGTH,
  XWING_CIPHERTEXT_BYTE_LENGTH,
} from '../../src/constants';
import { randomBytes } from '@noble/hashes/utils.js';

import { base64ToUint8Array } from '../../src/utils/converters';

describe('Test key wrapping functions', () => {
  it('should scuessfully generate hybrid key', async () => {
    const keys = genHybridKeys();

    expect(keys.publicKey).toBeInstanceOf(Uint8Array);
    expect(keys.secretKey).toBeInstanceOf(Uint8Array);

    expect(keys.publicKey.length).toBe(XWING_PUBLIC_KEY_LENGTH);
    expect(keys.secretKey.length).toBe(XWING_SECRET_KEY_LENGTH);
  });

  it('should generate identical keys for identical seeds', async () => {
    const seed = randomBytes(XWING_SEED_BYTE_LENGTH);
    const keys1 = genHybridKeys(seed);
    const keys2 = genHybridKeys(seed);

    expect(keys1).toStrictEqual(keys2);
  });

  it('should sucessufully decapsulate encapsulated secret', async () => {
    const keys = genHybridKeys();
    const { cipherText, sharedSecret } = encapsulateHybrid(keys.publicKey);
    expect(cipherText.length).toBe(XWING_CIPHERTEXT_BYTE_LENGTH);

    const result = decapsulateHybrid(cipherText, keys.secretKey);

    expect(result).toStrictEqual(sharedSecret);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(XWING_SECRET_KEY_LENGTH);
  });
  it('should decapsulate existing ciphertext', () => {
    const sharedSecretStr = 'zxuY95i1M//uq9efQ7iKAykU2bU5MXOyoH9her0j72Q=';
    const secretKeyStr = 'ZrR3PqNwfff15hdGkTg9FnMs11TQYxF0BCUVf/VH6GI=';
    const ciphertextStr =
      '15/qsiUXK1lcmNXVG//coX7UKS6j5KEkDkOjWbgdXjHMun5lLmVwvbiYMBolsmkmiZfJ81ByPmFhUkeB1sgkRIS0mSKXsBZVYMSzceNiCI8YY7DM1LFK7F3M5nLXRSqHTEH7DV1ghIdz3FnwcKqXcbqs/WsNUgjvARcTyUfNiGi3Z8uq6w0cJFbJcKZrr7GQNAWFu1wrjqsqWv3GFcqt91KFc0jB/WplWn/VYISQPqDVgSvYss3DJjMEh9ZqZ4AF0N2GIwU2CNQs4sbTSGoGpoYi5FEmiqVQQidWH5/9qeU+ipcjnvBs1sXepJuL7v7HKB2bl/mbJDm0BNcuBqUJERMJj5OoMBpNF3q6BHIfIRdznYSyz7RCiURTpOo2lB/uevngrapUeL4NqbidJCSWvTHgjq3+fLZZNU64tngg1GhsTIC9PzUnkGkEbRbJhOB0eemC8fGb8PMKcp5Spoivmk+bPFlbEonvIr7dzkeiujS06zovvUtX53OLHSGXkKhc3DDu2n7bQYmgL34nfAPw6rYejkdLEjfT0gNz56Jf5M5qrTjFEwdz1I881BUy9KgB1oxmLFn3sUL19LTpXWQNwY2mx9qLZGdiF6y/kj/A1Wx0Vz+glItAMw0LG6s8G7igq388srvPOT3e4fTypRILZaLXQJ9Fbccgcr+4L7Sh8MoPB/pIVNa1gQ4yqXpCRbtfCKfUs7CT9iwsCnMYOckjIjceUM20Z0sc6OwVuqt600z3SaxD8Hfhy6LeGbmzus3UnGMvOTgLNDGZFcoOdywKbKbIdoFCWR7eYUbpPQwIdn6ZBhiHmWTRKfjTQrGvBYGO3VEzrIzFmuhxpwGKAhah/f/ds1hWY1b64wiyNU3XrXGixbJMjiUnPA//14K2p8IL/Yymuw4nQiNtazUSNCn/b8IC8M85znDwS7lrqyzfdvuFu+oLmy3lIOx9GFXN6Uv6MxKeUTjaFrF+bu8C1dX4s9XOIYXpEFdTuEySpbsdPDKsQufj0XFZDQUw+CWsBHzlK/4IdY45TaEH8bddwXf51yg4z8rFr0Mtw5l3fOZQIYhe/T2CUrOaIM3AnhfZ6lNMN9KMjP98bPytNCbHBVjGko1+G4lTXgj278lBWoV7VlNAuYgzLemS32KVXWw16I0CxO2pjWQz++IJhwi18FhUtkt7DLHilT8ju43PnAe8eu9CuSBUuhMCOHRaUTcxAP3bEbLawio1LzmNnIrkAD7ndP4Gxfl0bAVvu3xxZIDQrbfwh4l45yksIuvaM6k8X0vSFz2HWEafa4EQRexGZRTAK320VTVEpzACO3fH71kpapTM/YEbLtimzdam465Vz3oj/rYjJKNHB0NzT5mlrHLUPUybfPfs6jgTFzWg44/f4ytOGIp16pGNZm8weGfHKGalEgKGBhLEdEBBJ+UNgKCRMYORptHKt49ZtAfQiqMEPQZM5eQHUwPbQJlw2RkK6Ehnaar8Ivy8EGzc/aruE03EIg==';

    const sharedSecret = base64ToUint8Array(sharedSecretStr);
    const secretKey = base64ToUint8Array(secretKeyStr);
    const cipherText = base64ToUint8Array(ciphertextStr);

    const result = decapsulateHybrid(cipherText, secretKey);
    expect(result).toStrictEqual(sharedSecret);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(XWING_SECRET_KEY_LENGTH);
  });
});
