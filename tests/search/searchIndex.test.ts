import { describe, expect, it } from "vitest";
import {
  desearializeIndices,
  getCurrentIndex,
  searializeIndices,
} from "../../src/search/createSearchIndex";
import { Email } from "../../src/utils/types";
import {
  decryptCurrentIndices,
  encryptCurrentIndices,
} from "../../src/search/searchIndex";
import { generateSymmetricKey } from "../../src/core/symmetric";
import { NONCE_LENGTH } from "../../src/utils/constants";

const emails: Email[] = [
  {
    id: "1",
    subject: "Moby Dick",
    body: "Call me Ishmael. Some years ago...",
    sender: "alice@email.com",
    recipient: ["bob@email.com"],
    date: new Date("2023-06-14T08:11:22.000Z"),
    labels: ["fiction"],
  },
  {
    id: "2",
    subject: "Zen and the Art of Motorcycle Maintenance",
    body: "I can see by my watch...",
    sender: "bob@email.com",
    recipient: ["alice@email.com", "eve@email.com"],
    date: new Date("2022-09-07T21:47:55.000Z"),
    labels: ["fiction", "self-help"],
  },
  {
    id: "3",
    subject: "Neuromancer",
    body: "The sky above the port was...",
    sender: "eve@email.com",
    recipient: ["alice@email.com", "bob@email.com"],
    date: new Date("2021-01-30T04:15:36.000Z"),
    labels: ["fiction"],
  },
  {
    id: "4",
    subject: "Zen and the Art of Archery",
    body: "At first sight it must seem...",
    sender: "bob@email.com",
    date: new Date("2021-01-30T04:15:36.000Z"),
    recipient: ["alice@email.com", "eve@email.com"],
    labels: ["non-fiction", "education"],
  },
];

describe("Test search index functions", () => {
  it("should sucesfully encrypt and decrypt current index", async () => {
    const indices = getCurrentIndex(emails);
    const results_before = indices.search("zen art motorcycle");

    const message = searializeIndices(indices);
    const key = await generateSymmetricKey();
    const repets = 0;
    const init_aux = "initial aux";

    const { nonce, ciphertext, iv, aux } = await encryptCurrentIndices(
      key,
      message,
      repets,
      init_aux,
    );
    const result = await decryptCurrentIndices(key, iv, ciphertext, aux);
    const decrypted_indices = desearializeIndices(result);
    const results_after = decrypted_indices.search("zen art motorcycle");

    expect(results_before).toStrictEqual(results_after);
    expect(aux).toBe(init_aux);
    expect(nonce).toBe(0);
  });

  it("should successfully wrap the nonce if repeats exceed the limit", async () => {
    const indices = getCurrentIndex(emails);
    const results_before = indices.search("zen art motorcycle");

    const message = searializeIndices(indices);
    const key = await generateSymmetricKey();
    const repets = Math.pow(2, NONCE_LENGTH * 8);
    const init_aux = "initial aux";

    const { nonce, ciphertext, iv, aux } = await encryptCurrentIndices(
      key,
      message,
      repets,
      init_aux,
    );
    const result = await decryptCurrentIndices(key, iv, ciphertext, aux);
    const decrypted_indices = desearializeIndices(result);
    const results_after = decrypted_indices.search("zen art motorcycle");

    expect(results_before).toStrictEqual(results_after);
    expect(aux).not.toBe(init_aux);
    expect(nonce).toBe(0);
  });
});
