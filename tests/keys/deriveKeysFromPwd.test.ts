import { describe, expect, it } from "vitest";
import {
  getKeyFromPasswordAndSalt,
  verifyKeyFromPasswordAndSaltHex,
  getKeyFromPasswordAndSaltHex,
  argon2Hex,
} from "../../src/keys/deriveKeysFromPwd";

describe("Test Argon2", () => {
  it("should get correct key from the password", async () => {
    const TEST_ARGON2_PARALLELISM = 7;
    const TEST_ARGON2_ITERATIONS = 20;
    const TEST_ARGON2_MEMORY_SIZE = 56;
    const TEST_ARGON2_TAG_LENGTH = 32;

    const test_password = "text demo";
    const test_salt = "123456789";

    const result = await argon2Hex(
      test_password,
      test_salt,
      TEST_ARGON2_PARALLELISM,
      TEST_ARGON2_ITERATIONS,
      TEST_ARGON2_MEMORY_SIZE,
      TEST_ARGON2_TAG_LENGTH,
    );
    expect(result).toBe(
      "ec2f7a502b4bfe7dc758c4c5120c7420830d42efdc7a78971743649b30cafb15",
    );
  });

  it("should sucessfully verify correct key", async () => {
    const test_password = "text demo";
    const test_salt = "123456789";
    const test_key = await getKeyFromPasswordAndSaltHex(
      test_password,
      test_salt,
    );
    const result = await verifyKeyFromPasswordAndSaltHex(
      test_password,
      test_salt,
      test_key,
    );
    expect(result).toBe(true);
  });

  it("should give the same result for the same password and salt", async () => {
    const test_password = "text demo";
    const test_salt = "123456789";
    const result1 = await getKeyFromPasswordAndSalt(test_password, test_salt);
    const result2 = await getKeyFromPasswordAndSalt(test_password, test_salt);
    expect(result1).toStrictEqual(result2);
  });

  it("should give different result for the same password but different salt", async () => {
    const test_password = "text demo";
    const test_salt_1 = "123456789";
    const test_salt_2 = "different salt";
    const result1 = await getKeyFromPasswordAndSaltHex(
      test_password,
      test_salt_1,
    );
    const result2 = await getKeyFromPasswordAndSaltHex(
      test_password,
      test_salt_2,
    );
    expect(result1).not.toBe(result2);
  });
});
