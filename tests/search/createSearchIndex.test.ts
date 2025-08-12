import { describe, expect, it } from "vitest";
import {
  desearializeIndices,
  getCurrentIndex,
  searializeIndices,
} from "../../src/search/createSearchIndex";
import { Email } from "../../src/utils/types";
import MiniSearch from "minisearch";

const emails: Email[] = [
  {
    id: "1",
    subject: "Moby Dick",
    body: "Call me Ishmael. Some years ago...",
    sender: "alice@email.com",
    recipient: ["bob@email.com"],
    date: "2023-06-14T08:11:22.000Z",
    labels: ["fiction"],
  },
  {
    id: "2",
    subject: "Zen and the Art of Motorcycle Maintenance",
    body: "I can see by my watch...",
    sender: "bob@email.com",
    recipient: ["alice@email.com", "eve@email.com"],
    date: "2022-09-07T21:47:55.000Z",
    labels: ["fiction", "self-help"],
  },
  {
    id: "3",
    subject: "Neuromancer",
    body: "The sky above the port was...",
    sender: "eve@email.com",
    recipient: ["alice@email.com", "bob@email.com"],
    date: "2021-01-30T04:15:36.000Z",
    labels: ["fiction"],
  },
  {
    id: "4",
    subject: "Zen and the Art of Archery",
    body: "At first sight it must seem...",
    sender: "bob@email.com",
    date: "2021-01-30T04:15:36.000Z",
    recipient: ["alice@email.com", "eve@email.com"],
    labels: ["non-fiction", "education"],
  },
];

describe("Test dummy search functions", () => {
  it("should sucessfully generate search index", async () => {
    const indices = getCurrentIndex(emails);
    const results = indices.search("zen art motorcycle");
    const expectedResult = [
      {
        id: "2",
        match: {
          art: ["subject"],
          motorcycle: ["subject"],
          zen: ["subject"],
        },
        queryTerms: ["zen", "art", "motorcycle"],
        score: 9.926306505038868,
        terms: ["zen", "art", "motorcycle"],
      },
      {
        id: "4",
        match: {
          art: ["subject"],
          zen: ["subject"],
        },
        queryTerms: ["zen", "art"],
        score: 3.7144222958250506,
        terms: ["zen", "art"],
      },
    ];

    expect(results).toStrictEqual(expectedResult);
  });

  it("should sucessfully generate search index", async () => {
    const indices = getCurrentIndex(emails);
    const results = indices.search("zen art motorcycle");

    const uint8 = searializeIndices(indices);
    const deserialized_indices = desearializeIndices(uint8);
    const results_after = indices.search("zen art motorcycle");

    expect(deserialized_indices).instanceOf(MiniSearch);
    expect(results).toStrictEqual(results_after);
  });
});
