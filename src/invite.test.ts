import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  INVITE_MAX,
  INVITE_PASTE_MAX,
  compactInvite,
  lanCodeFromInput,
  looksLikeBarePairingCode,
  looksLikeInvite,
} from "./invite.ts";

describe("invite lockstep", () => {
  it("caps match internet.rs", () => {
    assert.equal(INVITE_MAX, 1024);
    assert.equal(INVITE_PASTE_MAX, 4096);
  });

  it("compactInvite drops wrapping", () => {
    assert.equal(compactInvite("Fwb1-ABC\n"), "fwb1-abc");
    assert.equal(compactInvite("`endpointX-123456`"), "endpointx-123456");
  });

  it("looksLikeInvite vs bare pairing code", () => {
    assert.equal(looksLikeInvite("123456"), false);
    assert.equal(looksLikeBarePairingCode("123456"), true);
    assert.equal(looksLikeBarePairingCode("123-456"), true);
    assert.equal(looksLikeBarePairingCode("123.456"), true);
    assert.equal(looksLikeBarePairingCode("12345"), false);
    assert.equal(looksLikeBarePairingCode("1234567"), false);
    assert.equal(looksLikeInvite("endpointabc-123456"), true);
    assert.equal(looksLikeBarePairingCode("endpointabc-123456"), false);
    const id = "ab".repeat(32);
    assert.equal(looksLikeInvite(`fwb1-${id}-445566`), true);
    assert.equal(looksLikeBarePairingCode(`fwb1-${id}-445566`), false);
    assert.equal(looksLikeInvite(`fwb2-${id}-778899-dead`), true);
  });

  it("lanCodeFromInput lockstep internet.rs ts_lan_code", () => {
    const id = "ab".repeat(32);
    assert.equal(lanCodeFromInput(`fwb1-${id}-445566`), "445566");
    assert.equal(lanCodeFromInput("12ab34"), "1234");
    assert.equal(lanCodeFromInput("123-456"), "123456");
    assert.equal(lanCodeFromInput("1234567"), "1234567");
    assert.equal(lanCodeFromInput("fwb1-deadbeef"), "");
    assert.equal(lanCodeFromInput("fwb3-123456"), "");
    assert.equal(lanCodeFromInput("endpoint-123456"), "");
    assert.equal(lanCodeFromInput("endpointabc-123456"), "123456");
    assert.equal(lanCodeFromInput("endpointabc-123456-"), "123456");
    assert.equal(lanCodeFromInput("endpointabc-123456-de"), "123456");
  });
});
