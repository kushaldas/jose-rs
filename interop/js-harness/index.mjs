#!/usr/bin/env node
// JS side of the jose-rs <-> panva/jose interop harness.
// Mirrors the subcommand surface of interop/rust-harness/src/main.rs.
//
// All I/O is JSON on stdin/stdout; errors go to stderr and the process exits
// non-zero on failure.

import { readFileSync } from 'node:fs'
import {
  generateKeyPair,
  generateSecret,
  exportJWK,
  importJWK,
  CompactSign,
  compactVerify,
  SignJWT,
  jwtVerify,
  decodeProtectedHeader,
  CompactEncrypt,
  compactDecrypt,
  FlattenedEncrypt,
  flattenedDecrypt,
  GeneralEncrypt,
  generalDecrypt,
} from 'jose'

// Node's "ExperimentalWarning: ML-DSA-* Web Crypto API algorithm…" is
// suppressed by the driver (run-interop.sh sets
// NODE_OPTIONS=--disable-warning=ExperimentalWarning). A process-level
// 'warning' listener does NOT replace Node's default printer, so this
// has to be set before the process starts.

function parseArgs(argv) {
  const [cmd, ...rest] = argv
  let alg
  let enc
  let crv
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]
    if (a.startsWith('--alg=')) alg = a.slice('--alg='.length)
    else if (a === '--alg') { alg = rest[i + 1]; i++ }
    else if (a.startsWith('--enc=')) enc = a.slice('--enc='.length)
    else if (a === '--enc') { enc = rest[i + 1]; i++ }
    else if (a.startsWith('--crv=')) crv = a.slice('--crv='.length)
    else if (a === '--crv') { crv = rest[i + 1]; i++ }
  }
  return { cmd, alg, enc, crv }
}

function readStdin() {
  return readFileSync(0, 'utf8')
}

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n')
}

function b64uEncode(buf) {
  return Buffer.from(buf).toString('base64url')
}
function b64uDecode(s) {
  return new Uint8Array(Buffer.from(s, 'base64url'))
}

const JWE_KW_ALGS = new Set(['A128KW', 'A192KW', 'A256KW'])

async function genKey(alg, enc, crv) {
  if (!alg) throw new Error('--alg is required')
  if (alg === 'ECDH-ES') {
    // panva takes the JOSE agreement `alg` value here and maps it to the ECDH
    // primitive with the requested curve; `use: enc` and the `alg` pin are added
    // afterwards so the key says what it is for, exactly as the Rust harness
    // pins it.
    if (!crv) throw new Error('gen-key --alg ECDH-ES requires --crv')
    const { privateKey } = await generateKeyPair(alg, { crv, use: 'enc', extractable: true })
    const jwk = await exportJWK(privateKey)
    jwk.alg = alg
    jwk.use = 'enc'
    emit(jwk)
    return
  }
  if (JWE_KW_ALGS.has(alg) || alg === 'dir') {
    // Symmetric JWE key. For `dir` the secret *is* the CEK, so its size
    // follows `enc`; for AES-KW it follows the wrapping alg.
    if (alg === 'dir' && !enc) throw new Error('gen-key --alg dir requires --enc')
    const secret = await generateSecret(alg === 'dir' ? enc : alg, { extractable: true })
    const jwk = await exportJWK(secret)
    jwk.alg = alg
    emit(jwk)
    return
  }
  const { privateKey } = await generateKeyPair(alg, { extractable: true })
  const jwk = await exportJWK(privateKey)
  // Pin alg so a caller (panva or jose-rs) can use the JWK without hinting.
  if (!jwk.alg) jwk.alg = alg
  emit(jwk)
}

async function exportPub() {
  // Derive a public JWK by stripping private fields from the input JSON.
  // Re-importing/re-exporting via SubtleCrypto would require extractable
  // keys, which importJWK does not produce by default — and round-tripping
  // buys us nothing beyond a schema check the consumer is about to do anyway.
  const jwk = JSON.parse(readStdin())
  const privateFields = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'priv']
  for (const f of privateFields) delete jwk[f]
  emit(jwk)
}

async function signCompact(alg) {
  if (!alg) throw new Error('--alg is required')
  const { jwk, payload_b64u, header } = JSON.parse(readStdin())
  if (header && ('alg' in header)) throw new Error('header input must not override `alg`')
  const key = await importJWK(jwk, alg)
  const jws = await new CompactSign(b64uDecode(payload_b64u))
    .setProtectedHeader({ ...(header ?? {}), alg })
    .sign(key)
  emit({ jws })
}

async function verifyCompact(alg) {
  if (!alg) throw new Error('--alg is required')
  const { jwk, jws } = JSON.parse(readStdin())
  // Sanity: the token must declare the alg the matrix expects.
  const hdr = decodeProtectedHeader(jws)
  if (hdr.alg !== alg) {
    throw new Error(`token alg ${hdr.alg} does not match expected ${alg}`)
  }
  const key = await importJWK(jwk, alg)
  const { payload, protectedHeader } = await compactVerify(jws, key, { algorithms: [alg] })
  emit({ ok: true, payload_b64u: b64uEncode(payload), protected_header: protectedHeader })
}

async function signJwt(alg) {
  if (!alg) throw new Error('--alg is required')
  const { jwk, claims } = JSON.parse(readStdin())
  const key = await importJWK(jwk, alg)
  const jwt = await new SignJWT(claims)
    .setProtectedHeader({ alg, typ: 'JWT' })
    .sign(key)
  emit({ jwt })
}

async function verifyJwt(alg) {
  if (!alg) throw new Error('--alg is required')
  const { jwk, jwt } = JSON.parse(readStdin())
  const hdr = decodeProtectedHeader(jwt)
  if (hdr.alg !== alg) {
    throw new Error(`token alg ${hdr.alg} does not match expected ${alg}`)
  }
  const key = await importJWK(jwk, alg)
  // Interop cares about signature + wire format, not iss/aud/exp. Ignore
  // the default required checks so the harness doesn't reject valid JWTs
  // whose claims the Rust side happened to omit.
  const { payload } = await jwtVerify(jwt, key, {
    algorithms: [alg],
    requiredClaims: [],
    clockTolerance: 300,
  })
  emit({ ok: true, claims: payload })
}

async function encryptCompact(alg, enc) {
  if (!alg) throw new Error('--alg is required')
  if (!enc) throw new Error('--enc is required')
  const { jwk, plaintext_b64u, header } = JSON.parse(readStdin())
  if (header && ('alg' in header || 'enc' in header)) {
    throw new Error('header input must not override `alg` / `enc`')
  }
  if (jwk.alg !== alg) throw new Error(`JWK alg ${jwk.alg} does not match expected ${alg}`)
  const key = await importJWK(jwk, alg)
  const jwe = await new CompactEncrypt(b64uDecode(plaintext_b64u))
    .setProtectedHeader({ ...(header ?? {}), alg, enc })
    .encrypt(key)
  emit({ jwe })
}

async function decryptCompact(alg, enc) {
  if (!alg) throw new Error('--alg is required')
  if (!enc) throw new Error('--enc is required')
  const { jwk, jwe } = JSON.parse(readStdin())
  const hdr = decodeProtectedHeader(jwe)
  if (hdr.alg !== alg) throw new Error(`token alg ${hdr.alg} does not match expected ${alg}`)
  if (hdr.enc !== enc) throw new Error(`token enc ${hdr.enc} does not match expected ${enc}`)
  const key = await importJWK(jwk, alg)
  const { plaintext, protectedHeader } = await compactDecrypt(jwe, key, {
    keyManagementAlgorithms: [alg],
    contentEncryptionAlgorithms: [enc],
  })
  emit({ ok: true, plaintext_b64u: b64uEncode(plaintext), protected_header: protectedHeader })
}

/**
 * Flattened JWE JSON Serialization (RFC 7516 §7.2.2), emitted as a JSON
 * *string* in `jwe` so the matrix plumbing is identical to the compact cells.
 */
async function encryptFlattened(alg, enc) {
  if (!alg) throw new Error('--alg is required')
  if (!enc) throw new Error('--enc is required')
  const { jwk, plaintext_b64u, header, aad_b64u, unprotected, recipient_header } =
    JSON.parse(readStdin())
  for (const [name, value] of Object.entries({ header, unprotected, recipient_header })) {
    if (value && ('alg' in value || 'enc' in value)) {
      throw new Error(`${name} input must not override \`alg\` / \`enc\``)
    }
  }
  if (jwk.alg !== alg) throw new Error(`JWK alg ${jwk.alg} does not match expected ${alg}`)
  const key = await importJWK(jwk, alg)
  const enc_ = new FlattenedEncrypt(b64uDecode(plaintext_b64u))
    .setProtectedHeader({ ...(header ?? {}), alg, enc })
  // RFC 7516 §7.2.1 header locations that are NOT integrity protected. jose-rs
  // refuses to emit these, so this is the only side of the pair that can
  // produce them — which makes it the interesting direction to test.
  if (unprotected) enc_.setSharedUnprotectedHeader(unprotected)
  if (recipient_header) enc_.setUnprotectedHeader(recipient_header)
  // External AAD (RFC 7516 §7.2.1): panva encodes it into the `aad` member and
  // folds the encoded text into the content AAD input, exactly as RFC 7516
  // §5.1 step 14 requires — which is what makes this cell meaningful.
  if (aad_b64u) enc_.setAdditionalAuthenticatedData(b64uDecode(aad_b64u))
  const jwe = await enc_.encrypt(key)
  emit({ jwe: JSON.stringify(jwe) })
}

async function decryptFlattened(alg, enc) {
  if (!alg) throw new Error('--alg is required')
  if (!enc) throw new Error('--enc is required')
  const { jwk, jwe, aad_b64u } = JSON.parse(readStdin())
  const parsed = typeof jwe === 'string' ? JSON.parse(jwe) : jwe
  const hdr = decodeProtectedHeader(parsed)
  if (hdr.alg !== alg) throw new Error(`token alg ${hdr.alg} does not match expected ${alg}`)
  if (hdr.enc !== enc) throw new Error(`token enc ${hdr.enc} does not match expected ${enc}`)
  const key = await importJWK(jwk, alg)
  const { plaintext, protectedHeader } = await flattenedDecrypt(parsed, key, {
    keyManagementAlgorithms: [alg],
    contentEncryptionAlgorithms: [enc],
    ...(aad_b64u ? { additionalAuthenticatedData: b64uDecode(aad_b64u) } : {}),
  })
  emit({ ok: true, plaintext_b64u: b64uEncode(plaintext), protected_header: protectedHeader })
}

/// General JWE JSON Serialization (RFC 7516 §7.2.1), emit side.
///
/// jose-rs refuses to emit a *shared* unprotected header, so this is the only
/// side of the pair that can produce one — which is exactly why the cell is
/// worth running. Note that panva applies the same two structural rules we do:
/// header names must be disjoint across the three locations, and `dir` /
/// `ECDH-ES` may not address more than one recipient.
async function encryptGeneral(alg, enc) {
  if (!alg) throw new Error('--alg is required')
  if (!enc) throw new Error('--enc is required')
  const { jwks, plaintext_b64u, header, aad_b64u, unprotected, recipient_headers } =
    JSON.parse(readStdin())
  if (!Array.isArray(jwks) || jwks.length === 0) throw new Error('jwks must be a non-empty array')
  for (const [name, value] of Object.entries({ header, unprotected })) {
    if (value && ('alg' in value || 'enc' in value)) {
      throw new Error(`${name} input must not override \`alg\` / \`enc\``)
    }
  }
  for (const jwk of jwks) {
    if (jwk.alg !== alg) throw new Error(`JWK alg ${jwk.alg} does not match expected ${alg}`)
  }
  const ge = new GeneralEncrypt(b64uDecode(plaintext_b64u))
  ge.setProtectedHeader({ ...(header ?? {}), alg, enc })
  if (unprotected) ge.setSharedUnprotectedHeader(unprotected)
  for (const [i, jwk] of jwks.entries()) {
    const recipient = ge.addRecipient(await importJWK(jwk, alg))
    // One element per recipient, in order, each carrying the kid of its key.
    if (recipient_headers?.[i]) recipient.setUnprotectedHeader(recipient_headers[i])
  }
  if (aad_b64u) ge.setAdditionalAuthenticatedData(b64uDecode(aad_b64u))
  emit({ jwe: JSON.stringify(await ge.encrypt()) })
}

/// General JWE JSON Serialization, consume side.
///
/// panva resolves the recipient itself, trying the key against each element;
/// jose-rs makes the caller name the recipient instead (ADR 0014). The reported
/// headers are what panva authenticated, split the way it splits them.
async function decryptGeneral(alg, enc) {
  if (!alg) throw new Error('--alg is required')
  if (!enc) throw new Error('--enc is required')
  const { jwk, jwe, aad_b64u } = JSON.parse(readStdin())
  const parsed = typeof jwe === 'string' ? JSON.parse(jwe) : jwe
  const hdr = decodeProtectedHeader(parsed)
  if (hdr.alg !== alg) throw new Error(`token alg ${hdr.alg} does not match expected ${alg}`)
  if (hdr.enc !== enc) throw new Error(`token enc ${hdr.enc} does not match expected ${enc}`)
  const key = await importJWK(jwk, alg)
  const out = await generalDecrypt(parsed, key, {
    keyManagementAlgorithms: [alg],
    contentEncryptionAlgorithms: [enc],
    ...(aad_b64u ? { additionalAuthenticatedData: b64uDecode(aad_b64u) } : {}),
  })
  emit({
    ok: true,
    plaintext_b64u: b64uEncode(out.plaintext),
    protected_header: out.protectedHeader,
    recipient_count: (parsed.recipients ?? []).length,
    unprotected_header: { ...(out.sharedUnprotectedHeader ?? {}), ...(out.unprotectedHeader ?? {}) },
  })
}

async function main() {
  const { cmd, alg, enc, crv } = parseArgs(process.argv.slice(2))
  switch (cmd) {
    case 'gen-key': return genKey(alg, enc, crv)
    case 'export-pub': return exportPub()
    case 'sign-compact': return signCompact(alg)
    case 'verify-compact': return verifyCompact(alg)
    case 'sign-jwt': return signJwt(alg)
    case 'verify-jwt': return verifyJwt(alg)
    case 'encrypt-compact': return encryptCompact(alg, enc)
    case 'decrypt-compact': return decryptCompact(alg, enc)
    case 'encrypt-flattened': return encryptFlattened(alg, enc)
    case 'decrypt-flattened': return decryptFlattened(alg, enc)
    case 'encrypt-general': return encryptGeneral(alg, enc)
    case 'decrypt-general': return decryptGeneral(alg, enc)
    default: throw new Error(`unknown subcommand: ${cmd}`)
  }
}

main().catch((e) => {
  process.stderr.write(`jose-interop-js: ${e?.stack ?? e}\n`)
  process.exit(1)
})
