//import kemBuilder from 'pqc-kem-<algoName>.js'
import kemBuilder from "@dashlane/pqc-kem-kyber512-node";
import hkdf from "js-crypto-hkdf";

const kyber = require("crystals-kyber");
const webcrypto = require("crypto").webcrypto;
const { SHA3 } = require("sha3");

// Function for checking equality of arrays
function isEqualArray(a, b) {
  if (a.length != b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
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

    const { publicKey, privateKey } = await kem.keypair();
    const { ciphertext, sharedSecret: sharedSecretA } = await kem.encapsulate(
      publicKey
    );
    const { sharedSecret: sharedSecretB } = await kem.decapsulate(
      ciphertext,
      privateKey
    );
    passed = isEqualArray(sharedSecretA, sharedSecretB);
  } catch (e) {
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

    passed = isEqualArray(pkA, pkB) && isEqualArray(skA, skB);
  } catch (e) {
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
    passed = isEqualArray(sharedSecretA, sharedSecretB);
  } catch (e) {
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
    const { publicKey: pk, privateKey: sk } = await kem.keypair_seeded(seed);

    const { ciphertext: ct } = await kem.encapsulate_internal(pk, seed);

    const { sharedSecret: ss } = await kem.decapsulate_internal(ct, sk);
    passed = isEqualArray(seed, ss);
  } catch (e) {
    console.log("pqc_modified_kem_works: " + console.log(e));
  }

  return passed;
}
function addvector(a, b) {
  return a.map((e, i) => e + b[i]);
}

// Test that double KEM protocol works
export async function pqc_doublekem_works() {
  let passed = false;
  try {
    const kem = await kemBuilder();

    // Alice starts the interaction
    let seedA = new Uint8Array(32);
    webcrypto.getRandomValues(seedA);
    const { publicKey: pkA, privateKey: skA } = await kem.keypair_seeded(seedA);
    let randA = new Uint8Array(1088);
    webcrypto.getRandomValues(randA);
    const ctA = { ciphertext: randA };

    // Bob replies and derives shared key
    let seedB = new Uint8Array(32);
    webcrypto.getRandomValues(seedB);
    const ctB = await kem.encapsulate_internal(pkA, seedB);
    const ctAB = { ciphertext: addvector(ctA.ciphertext, ctB.ciphertext) };
    const { publicKey: pkB, privateKey: skB } = await kem.keypair_seeded(seedB);
    const sharedSecretB = await kem.decapsulate_internal(ctAB.ciphertext, skB);

    // Alice derives shared key
    const { sharedSecret: ss_B } = await kem.decapsulate_internal(
      ctB.ciphertext,
      skA
    );
    const { publicKey: pkB_star, privateKey: skB_star } =
      await kem.keypair_seeded(ss_B);
    if (isEqualArray(pkB_star, pkB)) {
      const sharedSecretA = await kem.decapsulate_internal(
        ctAB.ciphertext,
        skB_star
      );
      console.log(sharedSecretA);
      console.log(sharedSecretB);
      passed = isEqualArray(
        sharedSecretA.sharedSecret,
        sharedSecretB.sharedSecret
      );
    }
  } catch (e) {
    console.log("pqc_doublekem_works: " + console.log(e));
  }

  return passed;
}

// Test that KEMTLS protocol (without signatures) works
export async function pqc_kemtls_works() {
  let passed = false;

  try {
    let salt = new Uint8Array(32);
    webcrypto.getRandomValues(salt);
    const kem = await kemBuilder();
    // Alice starts the interaction
    const { publicKey: pkA, privateKey: skA } = await kem.keypair();

    // Bob replies
    const { publicKey: pkB, privateKey: skB } = await kem.keypair();
    const { ciphertext: ctB, sharedSecret: ssB } = await kem.encapsulate(pkA);
    // Alice replies and derives shared key
    const { sharedSecret: ssB_decaps } = await kem.decapsulate(ctB, skA);
    const { ciphertext: ctA, sharedSecret: ssA } = await kem.encapsulate(pkB);
    let master_str_A = String(ssA) + String(ssB_decaps);
    const secretA = await hkdf.compute(
      master_str_A,
      "SHA-256",
      32,
      "kemtls test",
      salt
    );

    // Bob derives shared key
    const { sharedSecret: ssA_decaps } = await kem.decapsulate(ctA, skB);
    let master_str_B = String(ssA_decaps) + String(ssB);
    const secretB = await hkdf.compute(
      master_str_B,
      "SHA-256",
      32,
      "kemtls test",
      salt
    );
    passed = isEqualArray(secretA.key, secretB.key);
  } catch (e) {
    console.log("pqc_kemtls_works: " + console.log(e));
  }
  return passed;
}

/*============================================
/ Kyber512 from crystals-kyber-javascript
=============================================*/

// Test that encaps/decaps works
export function ckj_kem_works() {
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

  return isEqualArray(ss1, ss2);
}

// Test that seeded keygen generates the same key for the same seed
export function ckj_seeded_keygen_same_seed_works() {
  let seed = new Uint8Array(32);
  webcrypto.getRandomValues(seed);

  let keysA = kyber.IndcpaKeyGen(seed);
  let pkA = keysA[0];
  let skA = keysA[1];

  let keysB = kyber.IndcpaKeyGen(seed);
  let pkB = keysB[0];
  let skB = keysB[1];

  return isEqualArray(pkA, pkB) && isEqualArray(skA, skB);
}

// Test that seeded keygen we can encaps/decaps
export function ckj_seeded_keygen_kem_works() {
  let seed = new Uint8Array(32);
  webcrypto.getRandomValues(seed);

  let keys = kyber.IndcpaKeyGen(seed);
  let pk = keys[0];
  let sk = keys[1];

  // do the missing FO transform to make sk compatible with encaps/decaps
  //----------------------------------------------
  // get hash of pk
  const buffer1 = Buffer.from(pk);
  const hash1 = new SHA3(256);
  hash1.update(buffer1);
  let pkh = hash1.digest();

  // read 32 random values (0-255) into a 32 byte array
  let rnd = new Uint8Array(32);
  webcrypto.getRandomValues(rnd); // web api cryptographically strong random values

  // concatenate to form IND-CCA2 private key: sk + pk + h(pk) + rnd
  for (let i = 0; i < pk.length; i++) {
    sk.push(pk[i]);
  }
  for (let i = 0; i < pkh.length; i++) {
    sk.push(pkh[i]);
  }
  for (let i = 0; i < rnd.length; i++) {
    sk.push(rnd[i]);
  }
  //----------------------------------------------

  // Encapulate and get a random 256 bit symmetric key (ss) and its encapsulation (c)
  let c_ss = kyber.Encrypt512(pk);
  let c = c_ss[0];
  let ss = c_ss[1];

  // To decapsulate and obtain the same symmetric key
  let ss_decaps = kyber.Decrypt512(c, sk);
  return isEqualArray(ss, ss_decaps);
}

// Test that modified encaps/decaps works
export function ckj_modified_kem_works() {
  let seed = new Uint8Array(32);
  webcrypto.getRandomValues(seed);

  let keys = kyber.IndcpaKeyGen(seed);
  let pk = keys[0];
  let sk = keys[1];

  let r = new Uint8Array(32);
  webcrypto.getRandomValues(r);

  let ct = kyber.IndcpaEncrypt(pk, seed, r);
  let seed_decaps = kyber.IndcpaDecrypt(ct, sk);

  return isEqualArray(seed, seed_decaps);
}

// Test that double KEM protocol works
export function ckj_doublekem_works() {
  let passed = false;
  // Alice starts the interaction
  let ctA = new Uint8Array(1088);
  webcrypto.getRandomValues(ctA);
  let alice_keys = kyber.KeyGen512();
  let pkA = alice_keys[0];
  let skA = alice_keys[1];

  // Bob replies and derives shared key
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
  if (isEqualArray(pkB_regen, pkB)) {
    let skB_regen = bob_keys_regen[1];
    let sharedSecretA = kyber.IndcpaDecrypt(ctA, skB_regen);
    passed = isEqualArray(sharedSecretA, sharedSecretB);
  }

  return passed;
}
