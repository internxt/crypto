export const AES_ALGORITHM = 'AES-GCM';
export const AES_KEY_BIT_LENGTH = 256;
export const AUX_BYTE_LEN = 16;
export const IV_LEN_BYTES = 16;

export const KEY_WRAPPING_ALGORITHM = 'AES-KW';
export const KEY_FORMAT = 'raw';
export const CONTEXT_WRAPPING = 'CRYPTO library 2025-08-22 18:10:00 key derived from ecc and kyber secrets';

export const ECC_ALGORITHM = 'X25519';

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

export const KYBER512_PUBLIC_KEY_LENGTH = 800;
export const KYBER512_SECRET_KEY_LENGTH = 1632;

export const KYBER768_PUBLIC_KEY_LENGTH = 1184;
export const KYBER768_SECRET_KEY_LENGTH = 2400;

export const KYBER1024_PUBLIC_KEY_LENGTH = 1568;
export const KYBER1024_SECRET_KEY_LENGTH = 3168;

export const KYBER_SEED_LENGTH = 64;

export const HASH_BIT_LEN = 256;

export const MAX_CACHE_SIZE = 600000000; // 600 MB
export const MAX_EMAIL_PER_BATCH = 100;
export const DB_LABEL = 'email';
export const DB_VERSION = 1;
