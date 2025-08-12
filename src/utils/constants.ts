export const AES_ALGORITHM = "AES-GCM";
export const AES_KEY_BIT_LENGTH = 256;
export const IV_LENGTH = 16;
export const NONCE_LENGTH = 4;
export const AUX_LEN = 128;
export const KEY_WRAPPING_ALGORITHM = "AES-KW";
export const KEY_FORMAT = "raw";

export const CURVE_NAME = "P-521";
export const ECC_ALGORITHM = "ECDH";

export const CONTEXT_LOGIN =
  "PQ MAIL 2025-07-26 16:18:03 key for opening identity keystore";
export const CONTEXT_KEYSTORE =
  "PQ MAIL 2025-07-30 16:18:03 key for opening encryption keys keystore";
export const CONTEXT_RECOVERY =
  "PQ MAIL 2025-07-30 16:20:00 key for account recovery";
export const CONTEXT_INDEX =
  "PQ MAIL 2025-07-30 17:20:00 key for protecting current search indices";

// Second recommended parameter set from RFC 9106
export const ARGON2ID_PARALLELISM = 3;
export const ARGON2ID_ITERATIONS = 4;
export const ARGON2ID_MEMORY_SIZE = 65536;
export const ARGON2ID_SALT_BYTE_LENGTH = 16;
export const ARGON2ID_OUTPUT_BYTE_LENGTH = 32;

export const IDENTITY_KEYSTORE_TAG = "Identity keystore";
export const ENCRYPTION_KEYSTORE_TAG = "Encryption keystore";
export const RECOVERY_KEYSTORE_TAG = "Key recovery keystroe";
export const INDEX_KEYSTORE_TAG = "Current encrypted indices";

export const KYBER_PUBLIC_KEY_LENGTH = 1184;
export const KYBER_SECRET_KEY_LENGTH = 2400;
export const KYBER_SEED_LENGTH = 64;

export const HASH_BIT_LEN = 256;
