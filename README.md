# crypto

A folder doublekem_js contains implementation for a custom key exchange algorithm with an off-channel authentication - double kem - based on [pqc-kem-kyber512-node](https://github.com/Dashlane/pqc.js/) and [crystals-kyber](https://github.com/antontutoveanu/crystals-kyber-javascript/tree/main). 
Also, it has an implementation of [KEMTLS](https://eprint.iacr.org/2020/534) (without certificates) based on [pqc-kem-kyber512-node](https://github.com/Dashlane/pqc.js/).

To run tests run the following from doublekem_js folder:

```npm install```

```npm test```

## Double kem protocol

The goal is for Alice and Bob to establish a shared secret ss. 
CPAPKE is an internal encryption/decryption scheme of Kyber. 
```

      ┌─────────────┐                                                            ┌─────────────┐                 
      │             │                                                            │             │                 
      │    Alice    │                                                            │     Bob     │                 
      └─────────────┘                                                            └─────────────┘                 
                                                                                                                 
                                                                                                                 
c_A <-getRandomValues(1088)                                                                                      
                                                                                                                 
(pk_A, sk_A) <- Kyber512.KeyGen()
                                                c_A, pk_A                                                        
                                  ────────────────────────────────────────►                                       
                                                                            seed <- getRandomValues(32)          
                                                                                                                 
                                                                            c_B <- CPAPKE.Enc(seed, pk_A)            
                                                                                                                 
                                                                            (pk_B, sk_B) <- Kyber512.KeyGen(seed)
                                                                                                                 
                                                                            c_AB <- c_A XOR c_B                  
                                                                                                                 
                                                 c_B, pk_B                  ss <- CPAPK.Dec(c_AB, sk_B)             
                                  ◄────────────────────────────────────────                                      
seed* <- CPAPKE.Dec(c_B, sk_A)                                                                                       
                                                                                                                 
(pk_B*, sk_B*) <- Kyber512.KeyGen(seed*)                                                                         
                                                                                                                 
if pk_B != pk_B*, abort                                                                                          
                                                                                                                 
c_AB = c_A XOR c_B                                                                                               
                                                                                                                 
ss <- Decaps(c_AB, sk_B)
```                                                                                           
