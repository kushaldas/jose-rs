#!/usr/bin/env node
// JS side of the jose-rs <-> panva/jose interop harness.
// Mirrors the subcommand surface of interop/rust-harness/src/main.rs.
//
// All I/O is JSON on stdin/stdout; errors go to stderr and the process exits
// non-zero on failure.

import { readFileSync } from 'node:fs'
import {
  generateKeyPair,
  exportJWK,
  importJWK,
  CompactSign,
  compactVerify,
  SignJWT,
  jwtVerify,
  decodeProtectedHeader,
} from 'jose'

// Node's "ExperimentalWarning: ML-DSA-* Web Crypto API algorithm…" is
// suppressed by the driver (run-interop.sh sets
// NODE_OPTIONS=--disable-warning=ExperimentalWarning). A process-level
// 'warning' listener does NOT replace Node's default printer, so this
// has to be set before the process starts.

function parseArgs(argv) {
  const [cmd, ...rest] = argv
  let alg
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]
    if (a.startsWith('--alg=')) alg = a.slice('--alg='.length)
    else if (a === '--alg') { alg = rest[i + 1]; i++ }
  }
  return { cmd, alg }
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

async function genKey(alg) {
  if (!alg) throw new Error('--alg is required')
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
  const { jwk, payload_b64u } = JSON.parse(readStdin())
  const key = await importJWK(jwk, alg)
  const jws = await new CompactSign(b64uDecode(payload_b64u))
    .setProtectedHeader({ alg })
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
  const { payload } = await compactVerify(jws, key, { algorithms: [alg] })
  emit({ ok: true, payload_b64u: b64uEncode(payload) })
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

async function main() {
  const { cmd, alg } = parseArgs(process.argv.slice(2))
  switch (cmd) {
    case 'gen-key': return genKey(alg)
    case 'export-pub': return exportPub()
    case 'sign-compact': return signCompact(alg)
    case 'verify-compact': return verifyCompact(alg)
    case 'sign-jwt': return signJwt(alg)
    case 'verify-jwt': return verifyJwt(alg)
    default: throw new Error(`unknown subcommand: ${cmd}`)
  }
}

main().catch((e) => {
  process.stderr.write(`jose-interop-js: ${e?.stack ?? e}\n`)
  process.exit(1)
})
