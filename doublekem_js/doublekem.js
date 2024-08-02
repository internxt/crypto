//import kemBuilder from 'pqc-kem-<algoName>.js'
import kemBuilder from "@dashlane/pqc-kem-kyber512-node";

const kyber = require("crystals-kyber");
const webcrypto = require("crypto").webcrypto;
var assert = require("assert");

// Function for checking equality of objects
function deepEqual(a, b) {
  try {
    assert.deepEqual(a, b);
  } catch (error) {
    if (error.name === "AssertionError") {
      return false;
    }
    throw error;
  }
  return true;
}

/*============================================
/ Kyber512 from dashlane/pqc-kem-kyber512-node
=============================================*/

// Test that encaps/decaps works
export async function pqc_kem_works() {
  let passed = false;
  try {
    const kem = await kemBuilder();

    const { publicKey, privateKey } = await kem.keypair().catch((e) => {
      console.log(e);
    });
    const { ciphertext, sharedSecret: sharedSecretA } = await kem
      .encapsulate(publicKey)
      .catch((e) => {
        console.log(e);
      });
    const { sharedSecret: sharedSecretB } = await kem.decapsulate(
      ciphertext,
      privateKey
    );
    passed = deepEqual(sharedSecretA, sharedSecretB);
  } catch (error) {
    console.log("pqc_kem_works: " + console.log(e));
  }

  return passed;
}

// Test that seeded keygen generates the same key for the same seed
export async function pqc_seeded_keygen_same_seed_works() {
  let passed = false;
  try {
    const kem = await kemBuilder();

    let secret = new Uint8Array(32);
    webcrypto.getRandomValues(secret);

    const { publicKey: pkA, privateKey: skA } = await kem.keypair_seeded(
      secret
    );
    const { publicKey: pkB, privateKey: skB } = await kem.keypair_seeded(
      secret
    );

    passed = deepEqual(pkA, pkB) && deepEqual(skA, skB);
  } catch (error) {
    console.log("pqc_seeded_keygen_same_seed_works: " + console.log(e));
  }

  return passed;
}

// Test that seeded keygen we can encaps/decaps
export async function pqc_seeded_keygen_kem_works() {
  let passed = false;
  try {
    const kem = await kemBuilder();

    let secret = new Uint8Array(32);
    webcrypto.getRandomValues(secret);

    const { publicKey, privateKey } = await kem.keypair_seeded(secret);

    const { ciphertext, sharedSecret: sharedSecretA } = await kem.encapsulate(
      publicKey
    );
    const { sharedSecret: sharedSecretB } = await kem.decapsulate(
      ciphertext,
      privateKey
    );
    passed = deepEqual(sharedSecretA, sharedSecretB);
  } catch (error) {
    console.log("pqc_seeded_keygen_kem_works: " + console.log(e));
  }

  return passed;
}

// Test that modified encaps/decaps works
export async function pqc_modified_kem_works() {
  let passed = false;

  try {
    let seed = new Uint8Array(32);
    webcrypto.getRandomValues(seed);

    const kem = await kemBuilder();
    const { publicKey, privateKey } = await kem.keypair_seeded(seed);

    const { ciphertext } = await kem.encapsulate_internal(publicKey, seed);

    const { sharedSecret } = await kem.decapsulate_internal(
      ciphertext,
      privateKey
    );
    passed = deepEqual(seed, sharedSecret);
  } catch (error) {
    console.log("pqc_modified_kem_works: " + console.log(e));
  }

  return passed;
}

// Test that double KEM protocol works
export async function pqc_doublekem_works() {
  let passed = false;
  try {
    const kem = await kemBuilder();

    // Alice starts the interaction
    let randA = new Uint8Array(1088);
    webcrypto.getRandomValues(randA);
    const ctA = { ciphertext: randA };
    const { publicKey: pkA, privateKey: skA } = await kem.keypair();

    // Bob replied and derives shared key
    let seedB = new Uint8Array(32);
    webcrypto.getRandomValues(seedB);
    const { publicKey: pkB, privateKey: skB } = await kem.keypair_seeded(seedB);
    const { ciphertext: ctB } = await kem.encapsulate_internal(pkA, seedB);
    const { sharedSecret: sharedSecretB } = await kem.decapsulate_internal(
      ctA,
      skB
    );

    // Alice derives shared key
    const { sharedSecret: seedA } = await kem.decapsulate_internal(ctB, skA);
    const { publicKey: pkB_regen, privateKey: skB_regen } =
      await kem.keypair_seeded(seedA);
    const { sharedSecret: sharedSecretA } = await kem.decapsulate_internal(
      ctA,
      skB_regen
    );

    passed = deepEqual(sharedSecretA, sharedSecretB);
  } catch (error) {
    console.log("pqc_doublekem_works: " + console.log(e));
  }

  return passed;
}

/*============================================
/ Kyber512 from crystals-kyber-javascript
=============================================*/

// Test that encaps/decaps works
export async function ckj_kem_works() {
  // To generate a public and private key pair (pk, sk)
  let pk_sk = kyber.KeyGen512();
  let pk = pk_sk[0];
  let sk = pk_sk[1];

  // To generate a random 256 bit symmetric key (ss) and its encapsulation (c)
  let c_ss = kyber.Encrypt512(pk);
  let c = c_ss[0];
  let ss1 = c_ss[1];

  // To decapsulate and obtain the same symmetric key
  let ss2 = kyber.Decrypt512(c, sk);

  return deepEqual(ss1, ss2);
}

// Test that seeded keygen generates the same key for the same seed
export async function ckj_seeded_keygen_same_seed_works() {
  let seed = new Uint8Array(32);
  webcrypto.getRandomValues(seed);

  let keysA = kyber.IndcpaKeyGen(seed);
  let pkA = keysA[0];
  let skA = keysA[1];

  let keysB = kyber.IndcpaKeyGen(seed);
  let pkB = keysB[0];
  let skB = keysB[1];

  return deepEqual(pkA, pkB) && deepEqual(skA, skB);
}

// Test that seeded keygen we can encaps/decaps
export async function ckj_seeded_keygen_kem_works() {
  let seed = new Uint8Array(32);
  webcrypto.getRandomValues(seed);

  let keys = kyber.IndcpaKeyGen(seed);
  let pk = keys[0];
  let sk = keys[1];

  // Encapulate and get a random 256 bit symmetric key (ss) and its encapsulation (c)
  let c_ss = kyber.Encrypt512(pk);
  let c = c_ss[0];
  let ss = c_ss[1];

  // To decapsulate and obtain the same symmetric key
  let ss_decaps = kyber.Decrypt512(c, sk);

  return deepEqual(ss, ss_decaps);
}

// Test that modified encaps/decaps works
export async function ckj_modified_kem_works() {
  let seed = new Uint8Array(32);
  webcrypto.getRandomValues(seed);

  let keys = kyber.IndcpaKeyGen(seed);
  let pk = keys[0];
  let sk = keys[1];

  let r = new Uint8Array(32);
  webcrypto.getRandomValues(r);

  let ct = kyber.IndcpaEncrypt(pk, seed, r);
  let seed_decaps = kyber.IndcpaDecrypt(ct, sk);

  return deepEqual(seed, seed_decaps);
}

// Test that double KEM protocol works
export async function ckj_doublekem_works() {
  // Alice starts the interaction
  let ctA = new Uint8Array(1088);
  webcrypto.getRandomValues(ctA);
  let alice_keys = kyber.KeyGen512();
  let pkA = alice_keys[0];
  let skA = alice_keys[1];

  // Bob replied and derives shared key
  let seedB = new Uint8Array(32);
  webcrypto.getRandomValues(seedB);
  let bob_keys = kyber.IndcpaKeyGen(seedB);
  let pkB = bob_keys[0];
  let skB = bob_keys[1];
  let r = new Uint8Array(32);
  webcrypto.getRandomValues(r);
  let ctB = kyber.IndcpaEncrypt(pkA, seedB, r);
  let sharedSecretB = kyber.IndcpaDecrypt(ctA, skB);

  // Alice derives shared key
  let seedA = kyber.IndcpaDecrypt(ctB, skA);
  let bob_keys_regen = kyber.IndcpaKeyGen(seedA);
  let pkB_regen = bob_keys_regen[0];
  let skB_regen = bob_keys_regen[1];
  let sharedSecretA = kyber.IndcpaDecrypt(ctA, skB_regen);

  return deepEqual(sharedSecretA, sharedSecretB);
}
