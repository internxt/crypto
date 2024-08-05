import { expect, test } from "vitest";
import {
  pqc_kem_works,
  pqc_seeded_keygen_same_seed_works,
  pqc_seeded_keygen_kem_works,
  pqc_modified_kem_works,
  pqc_doublekem_works,
  pqc_kemtls_works,
} from "./doublekem.js";
import {
  ckj_kem_works,
  ckj_seeded_keygen_same_seed_works,
  ckj_seeded_keygen_kem_works,
  ckj_modified_kem_works,
  ckj_doublekem_works,
} from "./doublekem.js";

/*============================================
/ Kyber512 from dashlane/pqc-kem-kyber512-node
=============================================*/

test("PQC encaps/decaps works", async () => {
  const result = await pqc_kem_works();
  expect(result).toBe(true);
});

test("PQC seeded keygen generates the same key for the same seed", async () => {
  const result = await pqc_seeded_keygen_same_seed_works();
  expect(result).toBe(true);
});

test("PQC seeded keygen works with encaps/decaps", async () => {
  const result = await pqc_seeded_keygen_kem_works();
  expect(result).toBe(true);
});

test("PQC modified encaps/decaps works", async () => {
  const result = await pqc_modified_kem_works();
  expect(result).toBe(true);
});

test("PQC-based double KEM works", async () => {
  const result = await pqc_doublekem_works();
  expect(result).toBe(true);
});

test("PQC-based KEMTLS works", async () => {
  const result = await pqc_kemtls_works();
  expect(result).toBe(true);
});

/*============================================
/ Kyber512 from crystals-kyber-javascript
=============================================*/

test("CKJ encaps/decaps works", () => {
  expect(ckj_kem_works()).toBe(true);
});

test("CKJ seeded keygen generates the same key for the same seed", () => {
  expect(ckj_seeded_keygen_same_seed_works()).toBe(true);
});

test("CKJ seeded keygen works with encaps/decaps", () => {
  expect(ckj_seeded_keygen_kem_works()).toBe(true);
});

test("CKJ modified encaps/decaps works", () => {
  expect(ckj_modified_kem_works()).toBe(true);
});

test("CKJ-based double KEM works", () => {
  expect(ckj_doublekem_works()).toBe(true);
});
