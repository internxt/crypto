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


// Test that dashlane/pqc-kem-kyber512-node Kyber512 works as expected
async function pqc_kem_works() {
  const kem = await kemBuilder();

  const { publicKey, privateKey } = await kem.keypair();
  const { ciphertext, sharedSecret: sharedSecretA } = await kem.encapsulate(
    publicKey
  );
  const { sharedSecret: sharedSecretB } = await kem.decapsulate(
    ciphertext,
    privateKey
  );

  console.log('PQC kem works');
  console.log(deepEqual(sharedSecretA, sharedSecretB));
}

pqc_kem_works();

// Test that after modification of keygen we can encaps/decaps
async function modification_keygen_pcq_works() {
  const kem = await kemBuilder();

  let secret = new Uint8Array(32);
  webcrypto.getRandomValues(secret);

  const { publicKey, privateKey } =  await kem.keypair_seeded(secret);

  const { ciphertext, sharedSecret: sharedSecretA } = await kem.encapsulate(
    publicKey
  );
  const { sharedSecret: sharedSecretB } = await kem.decapsulate(
    ciphertext,
    privateKey
  );

  console.log('Modified pqc key works');
  console.log(deepEqual(sharedSecretA, sharedSecretB));
 
}
modification_keygen_pcq_works();

// Test that modified encaps/decaps works as expected
async function modification_encaps_pcq_works() {
  
  let seed = new Uint8Array(32);
  webcrypto.getRandomValues(seed);

  const kem = await kemBuilder();
  const { publicKey, privateKey } = await kem.keypair_seeded(seed);

  
  const { ciphertext} = await kem.encapsulate_internal(
    publicKey,
    seed
  );


  const { sharedSecret } = await kem.decapsulate_internal(
    ciphertext,
    privateKey
  );

  console.log('Modified pqs encaps works');
  console.log(deepEqual(seed, sharedSecret));

}
modification_encaps_pcq_works();


// Test that double KEM based crystals-kyber Kyber512 works as expected
async function doublekem_pqc_works() {

  const kem = await kemBuilder();
  // Alice init
  let randA = new Uint8Array(1088);
  webcrypto.getRandomValues(randA);
  const ctA = {ciphertext: randA};
  const { publicKey: pkA, privateKey: skA } = await kem.keypair();

  // Bob reply
  let seedB = new Uint8Array(32);
  webcrypto.getRandomValues(seedB);
  const { publicKey: pkB, privateKey:  skB } = await kem.keypair_seeded(seedB);
  const { ciphertext : ctB}  = await kem.encapsulate_internal(pkA, seedB);


  const { sharedSecret: sharedSecretB }  = await kem.decapsulate_internal(ctA,skB);

 
  // Alice derives key
  const { sharedSecret: seedA }  = await kem.decapsulate_internal(ctB,skA);

  const { publicKey: pkB_regen, privateKey:  skB_regen }  = await kem.keypair_seeded(seedA);


  console.log('Alice got the same key');
  console.log(deepEqual(pkB_regen, pkB));
  let sharedSecretA = await kem.decapsulate_internal(ctA,skB_regen);

  console.log('Double KEM works');
  console.log(deepEqual(sharedSecretA, sharedSecretB));
}
doublekem_pqc_works();


// Test that crystals-kyber Kyber512 works as expected
async function crystals_kyber_works() {
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

  // Test function with KATs
  kyber.Test512();
  console.log('Test 512 works');
}

crystals_kyber_works();

// Test that double KEM based crystals-kyber Kyber512 works as expected
async function doublekem_crystals_kyber_works() {
  // Alice init
  let ctA = new Uint8Array(1088);
  webcrypto.getRandomValues(ctA);
  let alice_keys = kyber.KeyGen512();
  let pkA = alice_keys[0];
  let skA = alice_keys[1];

  // Bob reply
  let seedB = new Uint8Array(32);
  webcrypto.getRandomValues(seedB);
  let bob_keys = kyber.IndcpaKeyGen(seedB);
  let pkB = bob_keys[0];
  let skB = bob_keys[1];

  let r = new Uint8Array(32);
  webcrypto.getRandomValues(r); 
  let ctB = kyber.IndcpaEncrypt(pkA, seedB, r);
  let sharedSecretB = kyber.IndcpaDecrypt(ctA,skB);

  // Alice derives key
  let seedA = kyber.IndcpaDecrypt(ctB,skA);
  let bob_keys_regen = kyber.IndcpaKeyGen(seedA);
  let pkB_regen = bob_keys_regen[0];
  let skB_regen = bob_keys_regen[1];

  console.log('Alice got the same key');
  console.log(deepEqual(pkB_regen, pkB));
  let sharedSecretA = kyber.IndcpaDecrypt(ctA,skB_regen);

  console.log('Double KEM works');
  console.log(deepEqual(sharedSecretA, sharedSecretB));
}
doublekem_crystals_kyber_works();
