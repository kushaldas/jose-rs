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
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]
    if (a.startsWith('--alg=')) alg = a.slice('--alg='.length)
    else if (a === '--alg') { alg = rest[i + 1]; i++ }
    else if (a.startsWith('--enc=')) enc = a.slice('--enc='.length)
    else if (a === '--enc') { enc = rest[i + 1]; i++ }
  }
  return { cmd, alg, enc }
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

async function genKey(alg, enc) {
  if (!alg) throw new Error('--alg is required')
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

async function main() {
  const { cmd, alg, enc } = parseArgs(process.argv.slice(2))
  switch (cmd) {
    case 'gen-key': return genKey(alg, enc)
    case 'export-pub': return exportPub()
    case 'sign-compact': return signCompact(alg)
    case 'verify-compact': return verifyCompact(alg)
    case 'sign-jwt': return signJwt(alg)
    case 'verify-jwt': return verifyJwt(alg)
    case 'encrypt-compact': return encryptCompact(alg, enc)
    case 'decrypt-compact': return decryptCompact(alg, enc)
    default: throw new Error(`unknown subcommand: ${cmd}`)
  }
}

main().catch((e) => {
  process.stderr.write(`jose-interop-js: ${e?.stack ?? e}\n`)
  process.exit(1)
})
