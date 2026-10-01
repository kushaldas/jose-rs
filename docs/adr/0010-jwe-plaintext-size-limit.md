# ADR 0010 - Configurable JWE plaintext-size limit

- **Status:** Accepted
- **Date:** 2026-10-01
- **Component:** `src/jwe`

## Context

JWE decryption enforces a fixed serialized-token limit, but applications may
need a smaller bound on decrypted content. The compatibility inventory calls
out a missing configurable plaintext limit. This is independent of compression
and JSON serialization, which remain separate work.

## Decision

Add JweDecryptOptions::with_max_plaintext(bytes). The limit is inclusive and
measures returned plaintext bytes. Zero allows only empty plaintext. All
constructors retain their existing algorithm policies and default to no
additional plaintext limit. MAX_TOKEN_BYTES continues to apply independently.
The option applies to decrypt_with_options and the existing nested JWT path
that accepts those options. For nested JWTs it bounds the entire inner signed
token, not just the claims JSON. Convenience decrypt/decrypt_with_jwk entry
points retain their existing behavior; this PR does not add binding APIs.

After header policy checks, use the encoded ciphertext length to bound the
minimum possible plaintext before decoding ciphertext or recovering a key:

- AES-GCM plaintext has the same length as ciphertext.
- AES-CBC plaintext is at least ciphertext length minus 16 bytes, because
  valid PKCS#7 padding occupies one through sixteen bytes.

For valid unpadded base64url, decoded length is floor(encoded length * 3 / 4).
The existing token-size bound makes that arithmetic safe. This estimate does
not replace canonical base64url validation. Invalid encodings still fail.
No attacker-controlled limit is added to a length, avoiding limit overflow.

After successful authenticated decryption, check exact plaintext length.
Use a zeroizing owner so an over-limit result is wiped on rejection. Transfer
ownership without copying on success. CBC authentication-before-decryption
and padding validation remain unchanged.

## Boundaries and consequences

The limit is not a total memory or CPU budget. Header parsing and key handling
still use resources. CBC ciphertext and its decryption buffer may be up to one
16-byte block larger than the configured plaintext limit. Existing ciphertext
and token limits remain necessary. No compression is enabled.

Length-based rejection may happen before authentication; it conveys only a
public ciphertext-length fact and never returns plaintext. Exact CBC rejection
occurs only after authentication. Algorithm allowlists run before the new
preflight check, and a large plaintext limit never widens those allowlists.

The default API and wire format are unchanged. A configured limit intentionally
rejects otherwise-valid larger messages with InvalidToken.

## Validation

tests/jwe_plaintext_limit.rs covers all six content algorithms, inclusive
limits, zero/empty cases, base64 length remainders, CBC block boundaries,
usize::MAX, early rejection before key use, tampered authentication tags,
wrapped keys, canonical encoding, token size, and unchanged algorithm policy.
It also checks nested-JWT limits against the complete inner signed token and
CBC authentication failure before the exact plaintext-size check.
Existing RFC 7520 interoperability vectors and the full test suite continue
to cover the unchanged cryptographic implementation. The option has a runnable
rustdoc example. No dependency or feature changes are needed.
