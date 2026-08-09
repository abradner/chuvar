// Pure data-transform tests: no DOM, no API, no vi.mock — the same "props in,
// value out" shape TokensView.test.tsx uses for the view layer, applied here
// to the encode/decode boundary usePasskeys.ts sits behind.
import { describe, expect, it } from "vitest";
import {
  base64urlToBuffer,
  bufferToBase64url,
  decodeCreationOptions,
  decodeRequestOptions,
  encodeAssertionHeader,
  encodeAssertionResponse,
  encodeCreationResponse,
} from "./webauthnCodec";
import type { CredentialCreationOptionsJSON, CredentialRequestOptionsJSON } from "../../api/client";

describe("base64url <-> ArrayBuffer", () => {
  it("round-trips arbitrary bytes, including ones that need padding", () => {
    for (const bytes of [[], [0], [1, 2, 3], [255, 0, 128, 64, 32, 16]]) {
      const buf = new Uint8Array(bytes).buffer;
      const roundTripped = base64urlToBuffer(bufferToBase64url(buf));
      expect(new Uint8Array(roundTripped)).toEqual(new Uint8Array(buf));
    }
  });

  it("produces no padding characters ('=') and no '+'/'/' — the wire format's whole point", () => {
    const encoded = bufferToBase64url(new Uint8Array([251, 239, 190]).buffer);
    expect(encoded).not.toMatch(/[+/=]/);
  });

  it("decodes a value with URL-unsafe-looking characters replaced back correctly", () => {
    // Bytes chosen so the base64 alphabet naturally produces '+'/'/' in
    // standard encoding, to prove the '-'/'_' substitution round-trips.
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf]);
    const encoded = bufferToBase64url(bytes.buffer);
    expect(new Uint8Array(base64urlToBuffer(encoded))).toEqual(bytes);
  });
});

describe("decodeCreationOptions", () => {
  it("converts challenge, user.id, and excludeCredentials ids to ArrayBuffers, passing everything else through", () => {
    const json: CredentialCreationOptionsJSON = {
      publicKey: {
        rp: { id: "localhost", name: "Chuvar" },
        user: { id: bufferToBase64url(new Uint8Array([1, 2, 3]).buffer), name: "alex-laptop", displayName: "alex-laptop" },
        challenge: bufferToBase64url(new Uint8Array([9, 9, 9]).buffer),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: [{ type: "public-key", id: bufferToBase64url(new Uint8Array([4, 5]).buffer), transports: ["usb"] }],
        authenticatorSelection: { userVerification: "required" },
      },
    };

    const opts = decodeCreationOptions(json);

    expect(new Uint8Array(opts.publicKey!.challenge as ArrayBuffer)).toEqual(new Uint8Array([9, 9, 9]));
    expect(new Uint8Array((opts.publicKey!.user!.id as ArrayBuffer))).toEqual(new Uint8Array([1, 2, 3]));
    expect(opts.publicKey!.user!.name).toBe("alex-laptop");
    expect(opts.publicKey!.rp).toEqual({ id: "localhost", name: "Chuvar" });
    expect(opts.publicKey!.pubKeyCredParams).toEqual([{ type: "public-key", alg: -7 }]);
    expect(opts.publicKey!.authenticatorSelection).toEqual({ userVerification: "required" });

    const excluded = opts.publicKey!.excludeCredentials!;
    expect(excluded).toHaveLength(1);
    expect(new Uint8Array(excluded[0].id as ArrayBuffer)).toEqual(new Uint8Array([4, 5]));
    expect(excluded[0].transports).toEqual(["usb"]);
  });

  it("omits excludeCredentials when the server sent none", () => {
    const json: CredentialCreationOptionsJSON = {
      publicKey: {
        rp: { id: "localhost", name: "Chuvar" },
        user: { id: bufferToBase64url(new Uint8Array([1]).buffer), name: "a", displayName: "a" },
        challenge: bufferToBase64url(new Uint8Array([1]).buffer),
        pubKeyCredParams: [],
      },
    };

    expect(decodeCreationOptions(json).publicKey!.excludeCredentials).toBeUndefined();
  });
});

describe("decodeRequestOptions", () => {
  it("converts challenge and allowCredentials ids to ArrayBuffers", () => {
    const json: CredentialRequestOptionsJSON = {
      publicKey: {
        challenge: bufferToBase64url(new Uint8Array([7, 7]).buffer),
        rpId: "localhost",
        allowCredentials: [{ type: "public-key", id: bufferToBase64url(new Uint8Array([3]).buffer) }],
        userVerification: "required",
      },
    };

    const opts = decodeRequestOptions(json);

    expect(new Uint8Array(opts.publicKey!.challenge as ArrayBuffer)).toEqual(new Uint8Array([7, 7]));
    expect(opts.publicKey!.rpId).toBe("localhost");
    expect(new Uint8Array(opts.publicKey!.allowCredentials![0].id as ArrayBuffer)).toEqual(new Uint8Array([3]));
    expect(opts.publicKey!.userVerification).toBe("required");
  });
});

// fakeCredential builds a minimal PublicKeyCredential-shaped object — jsdom
// doesn't implement the real interface, and these tests only exercise this
// file's own field-mapping logic, not browser behaviour.
function fakeCredential(response: unknown): PublicKeyCredential {
  return {
    id: "cred-id-base64url",
    rawId: new Uint8Array([10, 20, 30]).buffer,
    type: "public-key",
    response,
  } as unknown as PublicKeyCredential;
}

describe("encodeCreationResponse", () => {
  it("base64url-encodes rawId and the response buffers, and includes the label", () => {
    const cred = fakeCredential({
      clientDataJSON: new Uint8Array([1]).buffer,
      attestationObject: new Uint8Array([2, 3]).buffer,
    });

    const body = encodeCreationResponse(cred, "yubikey") as {
      id: string;
      rawId: string;
      type: string;
      label: string;
      response: { clientDataJSON: string; attestationObject: string };
    };

    expect(body.id).toBe("cred-id-base64url");
    expect(body.type).toBe("public-key");
    expect(body.label).toBe("yubikey");
    expect(new Uint8Array(base64urlToBuffer(body.rawId))).toEqual(new Uint8Array([10, 20, 30]));
    expect(new Uint8Array(base64urlToBuffer(body.response.clientDataJSON))).toEqual(new Uint8Array([1]));
    expect(new Uint8Array(base64urlToBuffer(body.response.attestationObject))).toEqual(new Uint8Array([2, 3]));
  });
});

describe("encodeAssertionResponse / encodeAssertionHeader", () => {
  it("omits userHandle when the authenticator didn't return one", () => {
    const cred = fakeCredential({
      clientDataJSON: new Uint8Array([1]).buffer,
      authenticatorData: new Uint8Array([2]).buffer,
      signature: new Uint8Array([3]).buffer,
      userHandle: null,
    });

    const body = encodeAssertionResponse(cred) as { response: Record<string, unknown> };
    expect(body.response.userHandle).toBeUndefined();
  });

  it("includes userHandle, base64url-encoded, when the authenticator returned one", () => {
    const cred = fakeCredential({
      clientDataJSON: new Uint8Array([1]).buffer,
      authenticatorData: new Uint8Array([2]).buffer,
      signature: new Uint8Array([3]).buffer,
      userHandle: new Uint8Array([9, 9]).buffer,
    });

    const body = encodeAssertionResponse(cred) as { response: Record<string, unknown> };
    expect(new Uint8Array(base64urlToBuffer(body.response.userHandle as string))).toEqual(new Uint8Array([9, 9]));
  });

  it("encodeAssertionHeader produces a base64 string whose decoded content round-trips to the same JSON", () => {
    const cred = fakeCredential({
      clientDataJSON: new Uint8Array([1]).buffer,
      authenticatorData: new Uint8Array([2]).buffer,
      signature: new Uint8Array([3]).buffer,
    });

    const header = encodeAssertionHeader(cred);
    const decoded = JSON.parse(atob(header));
    expect(decoded.id).toBe("cred-id-base64url");
    expect(decoded.response.signature).toBe(bufferToBase64url(new Uint8Array([3]).buffer));
  });
});
