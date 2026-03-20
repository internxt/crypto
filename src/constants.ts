export const AES_KEY_BYTE_LENGTH = 32;
export const IV_LEN_BYTES = 12;

export const CONTEXT_ENC_KEYSTORE = 'CRYPTO library 2025-07-30 16:18:03 key for opening encryption keys keystore';
export const CONTEXT_RECOVERY = 'CRYPTO library 2025-07-30 16:20:00 key for account recovery';
export const CONTEXT_INDEX = 'CRYPTO library 2025-07-30 17:20:00 key for protecting current search indices';
export const CONTEXT_DERIVE = 'CRYPTO library 2025-08-27 17:08:00 derive one key from two keys';

// Second recommended parameter set from RFC 9106
export const ARGON2ID_PARALLELISM = 3;
export const ARGON2ID_ITERATIONS = 4;
export const ARGON2ID_MEMORY_SIZE = 65536;
export const ARGON2ID_SALT_BYTE_LENGTH = 16;
export const ARGON2ID_OUTPUT_BYTE_LENGTH = 32;

export const KYBER768_PUBLIC_KEY_LENGTH = 1184;
export const KYBER768_SECRET_KEY_LENGTH = 2400;
export const KYBER_SEED_LENGTH = 64;

export const MAX_CACHE_SIZE = 600000000; // 600 MB
export const MAX_EMAIL_PER_BATCH = 100;
export const DB_LABEL = 'email';
export const DB_VERSION = 1;

export const XWING_PUBLIC_KEY_LENGTH = 1216;
export const XWING_SECRET_KEY_LENGTH = 32;
export const XWING_SEED_BYTE_LENGTH = 32;
export const XWING_CIPHERTEXT_BYTE_LENGTH = 1120;
