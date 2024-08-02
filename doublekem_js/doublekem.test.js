import { expect, test } from 'vitest';
import { pqc_kem_works, pqc_seeded_keygen_same_seed_works, pqc_seeded_keygen_kem_works,  pqc_modified_kem_works, pqc_doublekem_works } from './doublekem.js';
import {ckj_kem_works, ckj_seeded_keygen_same_seed_works, ckj_seeded_keygen_kem_works, ckj_modified_kem_works, ckj_doublekem_works }  from './doublekem.js';
 
/*============================================
/ Kyber512 from dashlane/pqc-kem-kyber512-node
=============================================*/

test('PCQ encaps/decaps works', async () => {
  await expect(pqc_kem_works()).toBeTruthy();
});

test('PCQ seeded keygen generates the same key for the same seed', async () => {
    await expect(pqc_seeded_keygen_same_seed_works()).toBeTruthy();
  });
  
test('PCQ seeded keygen works with encaps/decaps', async () => {
    await expect(pqc_seeded_keygen_kem_works()).toBeTruthy();
  });

test('PCQ modified encaps/decaps works', async () => {
    await expect(pqc_modified_kem_works()).toBeTruthy();
  });

test('PCQ-based double KEM works', async () => {
    await expect(pqc_doublekem_works()).toBeTruthy();
  });

/*============================================
/ Kyber512 from crystals-kyber-javascript
=============================================*/

test('CKJ encaps/decaps works', async () => {
    await expect(ckj_kem_works()).toBeTruthy();
  });

test('CKJ seeded keygen generates the same key for the same seed', async () => {
    await expect(ckj_seeded_keygen_same_seed_works()).toBeTruthy();
  });

test('CKJ seeded keygen works with encaps/decaps', async () => {
    await expect(ckj_seeded_keygen_kem_works()).toBeTruthy();
  });

test('CKJ modified encaps/decaps works', async () => {
    await expect(ckj_modified_kem_works()).toBeTruthy();
  });

test('CKJ-based double KEM works', async () => {
    await expect(ckj_doublekem_works()).toBeTruthy();
  });