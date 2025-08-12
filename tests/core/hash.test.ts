import { describe, expect, it } from "vitest";
import { getHash } from "../../src/core/hash";
import { Buffer } from "buffer";

describe("Test getHash with blake3 test vectors", () => {
  it("extendSecret should pass test with input length 0 from blake3 team", async () => {
    const message = Buffer.from("");
    const result = await getHash(1048, [message]);
    const testResult = new Uint8Array(
      Buffer.from(
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d",
        "hex",
      ),
    );
    expect(result).toStrictEqual(testResult);
  });

  it("extendSecret should pass test with input length 1 from blake3 team", async () => {
    const message = Buffer.from([0]);
    const result = await getHash(1048, [message]);
    const testResult = new Uint8Array(
      Buffer.from(
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213c3a6cb8bf623e20cdb535f8d1a5ffb86342d9c0b64aca3bce1d31f60adfa137b358ad4d79f97b47c3d5e79f179df87a3b9776ef8325f8329886ba42f07fb138bb502f4081cbcec3195c5871e6c23e2cc97d3c69a613eba131e5f1351f3f1da786545e5",
        "hex",
      ),
    );
    expect(result).toStrictEqual(testResult);
  });

  it("extendSecret should pass test with input length 2 from blake3 team", async () => {
    const message = Buffer.from([0, 1]);
    const result = await getHash(1048, [message]);
    const testResult = new Uint8Array(
      Buffer.from(
        "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63d8386b22e2ddc05836b7c1bb693d92af006deb5ffbc4c70fb44d0195d0c6f252faac61659ef86523aa16517f87cb5f1340e723756ab65efb2f91964e14391de2a432263a6faf1d146937b35a33621c12d00be8223a7f1919cec0acd12097ff3ab00ab1",
        "hex",
      ),
    );
    expect(result).toStrictEqual(testResult);
  });

  function getBuffer(length: number) {
    const result = Array(length);
    let byte = 0;
    for (let i = 0; i < length; i++) {
      result[i] = byte;
      byte += 1;
      if (byte > 250) {
        byte = 0;
      }
    }
    return Buffer.from(result);
  }
  it("extendSecret should pass test with input length 7 from blake3 team", async () => {
    const message = getBuffer(7);
    const result = await getHash(1048, [message]);
    const testResult = new Uint8Array(
      Buffer.from(
        "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe66036ef6e6d1a8f54baa9fed1fc11c77cfb9cff65bae915045027046ebe0c01bf5a941f3bb0f73791d3fc0b84370f9f30af0cd5b0fc334dd61f70feb60dad785f070fef1f343ed933b49a5ca0d16a503f599a365a4296739248b28d1a20b0e2cc8975c",
        "hex",
      ),
    );
    expect(result).toStrictEqual(testResult);
  });

  it("extendSecret should pass test with input length 63 from blake3 team", async () => {
    const message = getBuffer(63);
    const result = await getHash(1048, [message]);
    const testResult = new Uint8Array(
      Buffer.from(
        "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b1197012b1e7d9af4d7cb7bdd1f3bb49a90a9b5dec3ea2bbc6eaebce77f4e470cbf4687093b5352f04e4a4570fba233164e6acc36900e35d185886a827f7ea9bdc1e5c3ce88b095a200e62c10c043b3e9bc6cb9b6ac4dfa51794b02ace9f98779040755",
        "hex",
      ),
    );
    expect(result).toStrictEqual(testResult);
  });

  it("extendSecret should pass test with input length 1023 from blake3 team", async () => {
    const message = getBuffer(1023);
    const result = await getHash(1048, [message]);
    const testResult = new Uint8Array(
      Buffer.from(
        "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11a182d27a591b05592b15607500e1e8dd56bc6c7fc063715b7a1d737df5bad3339c56778957d870eb9717b57ea3d9fb68d1b55127bba6a906a4a24bbd5acb2d123a37b28f9e9a81bbaae360d58f85e5fc9d75f7c370a0cc09b6522d9c8d822f2f28f485",
        "hex",
      ),
    );
    expect(result).toStrictEqual(testResult);
  });

  it("extendSecret should pass test with input length 102400 from blake3 team", async () => {
    const message = getBuffer(102400);
    const result = await getHash(1048, [message]);
    const testResult = new Uint8Array(
      Buffer.from(
        "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085e01c59dab908c04c3342b816941a26d69c2605ebee5ec5291cc55e15b76146e6745f0601156c3596cb75065a9c57f35585a52e1ac70f69131c23d611ce11ee4ab1ec2c009012d236648e77be9295dd0426f29b764d65de58eb7d01dd42248204f45f8e",
        "hex",
      ),
    );
    expect(result).toStrictEqual(testResult);
  });
});
