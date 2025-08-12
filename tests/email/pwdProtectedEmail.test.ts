import { describe, expect, it } from "vitest";
import {
  encryptPwdProtectedEmail,
  decryptPwdProtectedEmail,
} from "../../src/email/pwdProtectedEmail";
import { Email } from "../../src/utils/types";

describe("Test email crypto functions", () => {
  it("should encrypt and decrypt email sucessfully", async () => {
    const email: Email = {
      id: "42",
      subject: "Test subject",
      body: "Hi Bob, This is a test message. -Alice.",
      sender: "alice@example.com",
      recipient: ["bob@example.com"],
      date: "2025-03-4T08:11:22.000Z",
      labels: ["test label 1", "test label2"],
    };

    const sharedSecret = "test shared secret";

    const aux = "Email from Alice to Bob";

    const encryptedEmail = await encryptPwdProtectedEmail(
      sharedSecret,
      1,
      email,
      aux,
    );
    const decryptedEmail = await decryptPwdProtectedEmail(
      sharedSecret,
      encryptedEmail,
      aux,
    );
    expect(decryptedEmail).toStrictEqual(email);
  });
});
