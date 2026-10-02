//! Read-only capability reporting (L0).
//!
//! A capability table that is written by hand goes stale the first time a feature flag changes
//! what works. This one is written by hand **and checked by running the operations it
//! advertises**: `tests/capability_report.rs` signs, verifies, encrypts, decrypts and imports its
//! way through every row that claims to be usable, and refuses its way through every row that
//! claims not to be. A row that lies fails the test — which is the difference between a table and
//! documentation that drifted.
//!
//! # The four things a caller actually needs to distinguish
//!
//! * [`Availability::Supported`] — this build can do it, and the test suite proves it.
//! * [`Availability::RequiresFeature`] — the identifier is compiled in behind a Cargo feature;
//!   the row names the feature, and [`features`] says whether this build has it.
//! * [`Availability::RecognizedNotSupported`] — the identifier parses into our enum and has no
//!   operation behind it (`ES256K`). It is *not* `Supported` and *not* an unknown identifier;
//!   conflating those two is how "we support secp256k1" gets said by accident.
//! * [`Availability::RefusedByPolicy`] — we recognize the identifier and will not perform it,
//!   naming the reason (`RSA1_5`, `none`). A refusal is a design position, not a gap, and it is
//!   reported separately so a caller can tell "not yet" from "never".
//!
//! There is deliberately **no registration mechanism**: no global mutable algorithm table, no
//! `register()` call, no plugin hook. A registry that can be extended at runtime can also be
//! extended by a dependency, and after that the table is a description of whatever the process
//! happens to have loaded rather than of this crate. The data here is `const`-shaped and derived
//! from the same enums the operations take.

use crate::algorithm::{JweAlgorithm, JweEncryption, JwsAlgorithm};

/// What this build can do with an identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// The operation works in this build, and `tests/capability_report.rs` performs it.
    Supported,
    /// Compiled in only with the named Cargo feature.
    RequiresFeature(&'static str),
    /// Parses into our enum, but no operation is implemented (and none is planned here).
    RecognizedNotSupported,
    /// Recognized and refused on purpose; the string is the reason.
    RefusedByPolicy(&'static str),
}

impl Availability {
    /// Whether this build can perform the operation.
    ///
    /// `RequiresFeature` is resolved against the features this library was compiled with, so the
    /// answer is about *this* build rather than about some hypothetical one.
    pub fn is_available(self) -> bool {
        match self {
            Availability::Supported => true,
            Availability::RequiresFeature(feature) => feature_enabled(feature),
            Availability::RecognizedNotSupported | Availability::RefusedByPolicy(_) => false,
        }
    }

    /// Short label for the generated tables.
    pub fn label(self) -> &'static str {
        match self {
            Availability::Supported => "supported",
            Availability::RequiresFeature(_) => "feature-gated",
            Availability::RecognizedNotSupported => "recognized, unsupported",
            Availability::RefusedByPolicy(_) => "refused by policy",
        }
    }
}

/// An operation a caller might want.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Produce a signature.
    Sign,
    /// Check a signature.
    Verify,
    /// Encrypt (key management plus content encryption).
    Encrypt,
    /// Decrypt.
    Decrypt,
    /// Derive a shared key (ECDH-ES).
    DeriveKey,
    /// Generate a fresh key for this identifier.
    Generate,
    /// Import from the named representation.
    Import,
    /// Export to the named representation.
    Export,
    /// Compute a JWK thumbprint.
    Thumbprint,
}

impl Operation {
    /// Wire/API-facing name, used in the generated tables.
    pub fn as_str(self) -> &'static str {
        match self {
            Operation::Sign => "sign",
            Operation::Verify => "verify",
            Operation::Encrypt => "encrypt",
            Operation::Decrypt => "decrypt",
            Operation::DeriveKey => "deriveKey",
            Operation::Generate => "generate",
            Operation::Import => "import",
            Operation::Export => "export",
            Operation::Thumbprint => "thumbprint",
        }
    }
}

/// What kind of thing an identifier names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// JWS `alg` values.
    JwsAlgorithm,
    /// JWE `alg` values (key management).
    JweKeyManagement,
    /// JWE `enc` values (content encryption).
    JweContentEncryption,
    /// Key file formats accepted by `jwk::*` entry points.
    KeyFormat,
    /// Curves and key types.
    KeyType,
}

impl Kind {
    /// Table heading.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::JwsAlgorithm => "JWS algorithms",
            Kind::JweKeyManagement => "JWE key management",
            Kind::JweContentEncryption => "JWE content encryption",
            Kind::KeyFormat => "Key formats",
            Kind::KeyType => "Key types and curves",
        }
    }
}

/// One row of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    /// Which table this row belongs to.
    pub kind: Kind,
    /// The identifier as it appears on the wire (or the format's PEM label / type name).
    pub identifier: &'static str,
    /// Whether this build can perform it.
    pub availability: Availability,
    /// The operations advertised for it.
    pub operations: &'static [Operation],
    /// One sentence a caller needs: the feature name, the refusal reason, or the restriction.
    pub note: &'static str,
}

/// Cargo features that change capabilities, with whether this build has them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Feature {
    /// Cargo feature name.
    pub name: &'static str,
    /// Whether the library in front of the caller was compiled with it.
    pub enabled: bool,
    /// What it changes.
    pub effect: &'static str,
}

/// Whether a named feature is compiled into this build.
///
/// Unknown names are `false` rather than an error: this answers a question about a string the
/// caller already has, and a capability report that can fail is a report people skip.
pub fn feature_enabled(name: &str) -> bool {
    #[allow(clippy::match_like_matches_macro)] // documented three-way answer, not a predicate
    match name {
        "post-quantum" => cfg!(feature = "post-quantum"),
        "deprecated" => cfg!(feature = "deprecated"),
        // Named separately from the arms above so the `matches!`-shaped lint does not flatten
        // this into an expression and hide which features are knowable at all.
        _ => false,
    }
}

/// The feature list, with this build's settings.
pub fn features() -> Vec<Feature> {
    vec![
        Feature {
            name: "post-quantum",
            enabled: feature_enabled("post-quantum"),
            effect: "ML-DSA and composite signature algorithms, and their key generation",
        },
        Feature {
            name: "deprecated",
            enabled: feature_enabled("deprecated"),
            effect: "legacy identifiers this crate otherwise refuses: `RSA-OAEP` (SHA-1 label) \
                     and the `none` algorithm identifier",
        },
    ]
}

/// Every JWS algorithm identifier, with what this build does with it.
pub fn jws_algorithms() -> Vec<Capability> {
    const SIGN_VERIFY: &[Operation] = &[Operation::Sign, Operation::Verify];
    let mut rows = vec![
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::HS256.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "symmetric; requires a key of at least the digest size",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::HS384.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "symmetric",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::HS512.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "symmetric",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::RS256.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "RSA keys must be at least 2048 bits",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::RS384.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "RSA keys must be at least 2048 bits",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::RS512.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "RSA keys must be at least 2048 bits",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::PS256.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "RSASSA-PSS; an imported RSA-PSS key (SPKI with id-RSASSA-PSS parameters) is \
                   refused, so use a plain RSA key",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::PS384.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "RSASSA-PSS",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::PS512.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "RSASSA-PSS",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::ES256.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "requires crv P-256",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::ES384.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "requires crv P-384",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::ES512.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "requires crv P-521",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::EdDSA.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "legacy alias for Ed25519; a distinct allowlist entry from `Ed25519`",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::Ed25519.as_str(),
            availability: Availability::Supported,
            operations: SIGN_VERIFY,
            note: "fully specified identifier (RFC 9864); same primitive as `EdDSA`",
        },
        Capability {
            kind: Kind::JwsAlgorithm,
            identifier: JwsAlgorithm::ES256K.as_str(),
            availability: Availability::RecognizedNotSupported,
            operations: &[],
            note: "secp256k1 is not supported by the backend; the identifier parses and every \
                   operation refuses it",
        },
    ];

    // Post-quantum rows are listed either way: with the feature off they must stay *visible* as
    // unsupported, which is what "recognized identifiers remain visibly unsupported across
    // feature combinations" means in practice.
    #[cfg(feature = "post-quantum")]
    let pq: &[(&str, &[Operation], &str)] = &[
        ("ML-DSA-44", SIGN_VERIFY, "FIPS 204"),
        ("ML-DSA-65", SIGN_VERIFY, "FIPS 204"),
        ("ML-DSA-87", SIGN_VERIFY, "FIPS 204"),
        (
            "ML-DSA-44-ES256",
            SIGN_VERIFY,
            "composite, draft-ietf-jose-pq-composite-sigs",
        ),
        (
            "ML-DSA-65-ES256",
            SIGN_VERIFY,
            "composite, draft-ietf-jose-pq-composite-sigs",
        ),
        (
            "ML-DSA-87-ES384",
            SIGN_VERIFY,
            "composite, draft-ietf-jose-pq-composite-sigs",
        ),
        (
            "ML-DSA-44-Ed25519",
            SIGN_VERIFY,
            "composite, draft-ietf-jose-pq-composite-sigs",
        ),
        (
            "ML-DSA-65-Ed25519",
            SIGN_VERIFY,
            "composite, draft-ietf-jose-pq-composite-sigs",
        ),
        (
            "ML-DSA-87-Ed448",
            SIGN_VERIFY,
            "composite; Ed448 is available inside it, but not as a standalone key type",
        ),
    ];
    #[cfg(not(feature = "post-quantum"))]
    let pq: &[(&str, &[Operation], &str)] = &[
        ("ML-DSA-44", &[], "FIPS 204"),
        ("ML-DSA-65", &[], "FIPS 204"),
        ("ML-DSA-87", &[], "FIPS 204"),
        ("ML-DSA-44-ES256", &[], "composite"),
        ("ML-DSA-65-ES256", &[], "composite"),
        ("ML-DSA-87-ES384", &[], "composite"),
        ("ML-DSA-44-Ed25519", &[], "composite"),
        ("ML-DSA-65-Ed25519", &[], "composite"),
        ("ML-DSA-87-Ed448", &[], "composite"),
    ];
    for (identifier, operations, note) in pq {
        rows.push(Capability {
            kind: Kind::JwsAlgorithm,
            identifier,
            availability: pq_availability(identifier),
            operations: pq_operations(identifier, operations),
            note,
        });
    }

    rows.push(Capability {
        kind: Kind::JwsAlgorithm,
        identifier: "none",
        availability: Availability::RefusedByPolicy(
            "unsecured JWS/JWT: the `deprecated` feature exposes the identifier, and verification \
             of an unsecured token remains refused",
        ),
        operations: &[],
        note: "RFC 8725 §3.1 forbids accepting it; the identifier exists for inspection paths only",
    });
    rows
}

/// Every JWE key-management identifier.
pub fn jwe_algorithms() -> Vec<Capability> {
    const BOTH: &[Operation] = &[Operation::Encrypt, Operation::Decrypt];
    let key_based = [
        JweAlgorithm::A128KW,
        JweAlgorithm::A192KW,
        JweAlgorithm::A256KW,
    ];
    let mut rows: Vec<Capability> = key_based
        .iter()
        .map(|alg| Capability {
            kind: Kind::JweKeyManagement,
            identifier: alg.as_str(),
            availability: Availability::Supported,
            operations: BOTH,
            note: "AES key wrapping with an `oct` key of the matching size",
        })
        .collect();

    rows.extend([
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: JweAlgorithm::Dir.as_str(),
            availability: Availability::Supported,
            operations: BOTH,
            note: "the `enc` key is the recipient key; size must match the content encryption",
        },
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: JweAlgorithm::A128Gcmkw.as_str(),
            availability: Availability::Supported,
            operations: BOTH,
            note: "iv and tag are always library-generated, never read from a recipient header",
        },
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: JweAlgorithm::A192Gcmkw.as_str(),
            availability: Availability::Supported,
            operations: BOTH,
            note: "iv and tag are always library-generated",
        },
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: JweAlgorithm::A256Gcmkw.as_str(),
            availability: Availability::Supported,
            operations: BOTH,
            note: "iv and tag are always library-generated",
        },
        // RSA-OAEP (SHA-1 label) is feature-gated: the identifier itself is only compiled in
        // with `deprecated`, which is precisely the kind of fact a caller cannot discover from
        // the type signature and a capability table exists to say out loud.
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: rsa_oaep_identifier(),
            availability: if feature_enabled("deprecated") {
                Availability::Supported
            } else {
                Availability::RequiresFeature("deprecated")
            },
            operations: if feature_enabled("deprecated") {
                BOTH
            } else {
                &[]
            },
            note: "RSAES-OAEP with SHA-1 MGF1; compiled in only with `deprecated`, and keys \
                   below 2048 bits are refused",
        },
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: JweAlgorithm::RsaOaep256.as_str(),
            availability: Availability::Supported,
            operations: BOTH,
            note: "RSA-OAEP with SHA-256",
        },
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: JweAlgorithm::EcdhEs.as_str(),
            availability: Availability::Supported,
            operations: &[Operation::Encrypt, Operation::Decrypt, Operation::DeriveKey],
            note: "direct ECDH-ES; the whole key is the derived KEK, so each `enc` needs the \
                   matching key size",
        },
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: JweAlgorithm::EcdhEsA128kw.as_str(),
            availability: Availability::Supported,
            operations: &[Operation::Encrypt, Operation::Decrypt, Operation::DeriveKey],
            note: "general serialization is refused for this family (single recipient per element)",
        },
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: JweAlgorithm::EcdhEsA192kw.as_str(),
            availability: Availability::Supported,
            operations: &[Operation::Encrypt, Operation::Decrypt, Operation::DeriveKey],
            note: "single recipient",
        },
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: JweAlgorithm::EcdhEsA256kw.as_str(),
            availability: Availability::Supported,
            operations: &[Operation::Encrypt, Operation::Decrypt, Operation::DeriveKey],
            note: "single recipient",
        },
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: JweAlgorithm::Pbes2Hs256A128kw.as_str(),
            availability: Availability::Supported,
            operations: BOTH,
            note: "password-based: takes `Password`, and p2c is bounded (ADR 0021)",
        },
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: JweAlgorithm::Pbes2Hs384A192kw.as_str(),
            availability: Availability::Supported,
            operations: BOTH,
            note: "password-based",
        },
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: JweAlgorithm::Pbes2Hs512A256kw.as_str(),
            availability: Availability::Supported,
            operations: BOTH,
            note: "password-based",
        },
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: "RSA1_5",
            availability: Availability::RefusedByPolicy(
                "PKCS #1 v1.5 key encryption is a chosen-ciphertext oracle (BLEEP/BACA) and RFC \
                 8725 §4.1 forbids it",
            ),
            operations: &[],
            note: "never offered; the refusal names the algorithm so a misconfigured peer is \
                   visible",
        },
        Capability {
            kind: Kind::JweKeyManagement,
            identifier: "RSA-OAEP-384",
            availability: Availability::RecognizedNotSupported,
            operations: &[],
            note: "not in the backend's key-management set; the identifier is unknown to the \
                   parser rather than silently accepted",
        },
    ]);
    rows
}

/// Availability of a post-quantum identifier in this build.
///
/// The shape of this function is the point: availability is a statement about *this* build, and it
/// is checked by performing the operation. (`ML-DSA-87-Ed448` was the case that proved it — the
/// table guessed "recognized, unsupported" on the theory that the backend has no standalone
/// Ed448, and the executable test answered by signing and verifying successfully. The composite
/// carries Ed448 internally; only the standalone key type is missing, which is its own row.)
#[cfg(feature = "post-quantum")]
fn pq_availability(_identifier: &str) -> Availability {
    Availability::Supported
}

#[cfg(not(feature = "post-quantum"))]
fn pq_availability(_identifier: &str) -> Availability {
    Availability::RequiresFeature("post-quantum")
}

/// Operations for a post-quantum identifier in this build.
#[cfg(feature = "post-quantum")]
fn pq_operations<'a>(_identifier: &str, operations: &'a [Operation]) -> &'a [Operation] {
    operations
}

#[cfg(not(feature = "post-quantum"))]
fn pq_operations<'a>(_identifier: &str, _operations: &'a [Operation]) -> &'a [Operation] {
    &[]
}

/// The `RSA-OAEP` identifier, spelled the same whether or not the variant is compiled in.
///
/// Written as two cfg'd functions rather than one `if`, because the *variant path* has to exist
/// at compile time to be named.
#[cfg(feature = "deprecated")]
fn rsa_oaep_identifier() -> &'static str {
    // Resolved through the enum, so a rename cannot leave the table behind.
    JweAlgorithm::RsaOaep.as_str()
}

#[cfg(not(feature = "deprecated"))]
fn rsa_oaep_identifier() -> &'static str {
    "RSA-OAEP"
}

/// Every content-encryption identifier.
pub fn jwe_encryptions() -> Vec<Capability> {
    const BOTH: &[Operation] = &[Operation::Encrypt, Operation::Decrypt];
    [
        JweEncryption::A128CbcHs256,
        JweEncryption::A192CbcHs384,
        JweEncryption::A256CbcHs512,
        JweEncryption::A128GCM,
        JweEncryption::A192GCM,
        JweEncryption::A256GCM,
    ]
    .iter()
    .map(|enc| Capability {
        kind: Kind::JweContentEncryption,
        identifier: enc.as_str(),
        availability: Availability::Supported,
        operations: BOTH,
        note: "iv and tag are library-generated; `enc` is always integrity-protected in the \
               protected header",
    })
    .collect()
}

/// Key representations `jwk::*` can read and write.
pub fn key_formats() -> Vec<Capability> {
    const IMPORT: &[Operation] = &[Operation::Import];
    const IMPORT_EXPORT: &[Operation] = &[Operation::Import, Operation::Export];
    vec![
        Capability {
            kind: Kind::KeyFormat,
            identifier: "JWK (JSON)",
            availability: Availability::Supported,
            operations: IMPORT_EXPORT,
            note: "Jwk::from_json / Jwk::to_json",
        },
        Capability {
            kind: Kind::KeyFormat,
            identifier: "PKCS#8 DER / \"PRIVATE KEY\"",
            availability: Availability::Supported,
            operations: IMPORT_EXPORT,
            note: "RSA, EC P-256/P-384/P-521, Ed25519, X25519; export emits the narrower \
                   OneAsymmetricKey form (ADR 0022)",
        },
        Capability {
            kind: Kind::KeyFormat,
            identifier: "SPKI DER / \"PUBLIC KEY\"",
            availability: Availability::Supported,
            operations: IMPORT_EXPORT,
            note: "OKP/X25519 has no SPKI form in this backend and is refused by name",
        },
        Capability {
            kind: Kind::KeyFormat,
            identifier: "PKCS#1 DER / \"RSA PRIVATE KEY\"",
            availability: Availability::Supported,
            operations: IMPORT,
            note: "rebuilt from its parts and checked against itself (ADR 0023); multi-prime is \
                   refused",
        },
        Capability {
            kind: Kind::KeyFormat,
            identifier: "PKCS#1 \"RSA PUBLIC KEY\"",
            availability: Availability::Supported,
            operations: IMPORT,
            note: "import only; export uses SPKI",
        },
        Capability {
            kind: Kind::KeyFormat,
            identifier: "SEC1 DER / \"EC PRIVATE KEY\"",
            availability: Availability::Supported,
            operations: IMPORT,
            note: "must state its curve by name; explicit parameters are refused (ADR 0024)",
        },
        Capability {
            kind: Kind::KeyFormat,
            identifier: "Encrypted PKCS#8 / \"ENCRYPTED PRIVATE KEY\"",
            availability: Availability::Supported,
            operations: IMPORT_EXPORT,
            note: "PBES2 + PBKDF2-HMAC-SHA2 + AES-CBC only, with a bounded work budget (ADR 0025)",
        },
        Capability {
            kind: Kind::KeyFormat,
            identifier: "X.509 certificate / \"CERTIFICATE\"",
            availability: Availability::Supported,
            operations: IMPORT,
            note: "subject public key only; validates nothing about the certificate (ADR 0026)",
        },
        Capability {
            kind: Kind::KeyFormat,
            identifier: "PKCS#12 / JWK Set encryption",
            availability: Availability::RecognizedNotSupported,
            operations: &[],
            note: "not implemented; a JWK Set is read as plain JSON only",
        },
        Capability {
            kind: Kind::KeyFormat,
            identifier: "password-protected legacy PEM (Proc-Type/DEK-Info)",
            availability: Availability::RecognizedNotSupported,
            operations: &[],
            note: "recognized by the armor reader and refused: the encryption is its own key \
                   material, not a JOSE input",
        },
    ]
}

/// Key types and curves, and what restricts them.
pub fn key_types() -> Vec<Capability> {
    const USE: &[Operation] = &[
        Operation::Generate,
        Operation::Import,
        Operation::Export,
        Operation::Thumbprint,
    ];
    vec![
        Capability {
            kind: Kind::KeyType,
            identifier: "RSA",
            availability: Availability::Supported,
            operations: USE,
            note: "minimum 2048-bit modulus, enforced on import, generation and use",
        },
        Capability {
            kind: Kind::KeyType,
            identifier: "EC P-256",
            availability: Availability::Supported,
            operations: USE,
            note: "ES256, ECDH-ES",
        },
        Capability {
            kind: Kind::KeyType,
            identifier: "EC P-384",
            availability: Availability::Supported,
            operations: USE,
            note: "ES384, ECDH-ES",
        },
        Capability {
            kind: Kind::KeyType,
            identifier: "EC P-521",
            availability: Availability::Supported,
            operations: USE,
            note: "ES512, ECDH-ES",
        },
        Capability {
            kind: Kind::KeyType,
            identifier: "EC secp256k1",
            availability: Availability::RecognizedNotSupported,
            operations: &[],
            note: "no backend support; see ES256K",
        },
        Capability {
            kind: Kind::KeyType,
            identifier: "EC Brainpool curves",
            availability: Availability::RecognizedNotSupported,
            operations: &[],
            note: "no backend support; a Brainpool certificate or SEC1 file is refused naming the \
                   curve",
        },
        Capability {
            kind: Kind::KeyType,
            identifier: "OKP Ed25519",
            availability: Availability::Supported,
            operations: USE,
            note: "EdDSA / Ed25519; exports SPKI, unlike X25519",
        },
        Capability {
            kind: Kind::KeyType,
            identifier: "OKP X25519",
            availability: Availability::Supported,
            operations: USE,
            note: "key agreement only; `deriveKey` on a signing key (and the reverse) is refused",
        },
        Capability {
            kind: Kind::KeyType,
            identifier: "OKP Ed448 / X448",
            availability: Availability::RecognizedNotSupported,
            operations: &[],
            note:
                "not exposed by the backend; the composite ML-DSA-87-Ed448 scheme is a separate, \
                   feature-gated construction",
        },
        Capability {
            kind: Kind::KeyType,
            identifier: "oct",
            availability: Availability::Supported,
            operations: USE,
            note: "key size is checked against the algorithm that uses it",
        },
        Capability {
            kind: Kind::KeyType,
            identifier: "AKP (ML-DSA, composites)",
            availability: Availability::RequiresFeature("post-quantum"),
            operations: if feature_enabled("post-quantum") {
                USE
            } else {
                &[]
            },
            note: "composite encodings have no PKCS#8/SPKI form, so PEM export is refused",
        },
    ]
}

/// Every row, in table order.
pub fn all() -> Vec<Capability> {
    let mut rows = jws_algorithms();
    rows.extend(jwe_algorithms());
    rows.extend(jwe_encryptions());
    rows.extend(key_formats());
    rows.extend(key_types());
    rows
}

/// Look up one identifier.
pub fn find(kind: Kind, identifier: &str) -> Option<Capability> {
    all()
        .into_iter()
        .find(|row| row.kind == kind && row.identifier == identifier)
}

/// Identify the rows this build can actually perform.
pub fn available() -> Vec<Capability> {
    all()
        .into_iter()
        .filter(|row| row.availability.is_available())
        .collect()
}

/// Render the tables as Markdown, for generated documentation.
///
/// `docs/capabilities.md` is this function's output, and a test compares the two so the
/// committed tables cannot drift from the code (which the operation tests keep honest).
pub fn markdown() -> String {
    let mut out = String::new();
    out.push_str("# Capability tables\n\nGenerated by `cargo run --example capabilities`.\n");
    out.push_str(
        "`tests/capability_report.rs` performs every advertised operation, so a row that ",
    );
    out.push_str("overstates itself fails the test suite.\n\n");
    out.push_str("## Build features\n\n| feature | enabled here | effect |\n| --- | --- | --- |\n");
    for feature in features() {
        out.push_str(&format!(
            "| `{}` | {} | {} |\n",
            feature.name,
            if feature.enabled { "yes" } else { "no" },
            feature.effect
        ));
    }
    for kind in [
        Kind::JwsAlgorithm,
        Kind::JweKeyManagement,
        Kind::JweContentEncryption,
        Kind::KeyFormat,
        Kind::KeyType,
    ] {
        out.push_str(&format!("\n## {}\n\n", kind.as_str()));
        out.push_str("| identifier | status | operations | note |\n| --- | --- | --- | --- |\n");
        for row in all().into_iter().filter(|row| row.kind == kind) {
            let operations = if row.operations.is_empty() {
                "—".to_string()
            } else {
                row.operations
                    .iter()
                    .map(|op| op.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let status = match row.availability {
                Availability::RequiresFeature(feature) => {
                    format!("feature-gated (`{feature}`)")
                }
                Availability::RefusedByPolicy(reason) => {
                    format!("refused by policy — {reason}")
                }
                other => other.label().to_string(),
            };
            out.push_str(&format!(
                "| `{}` | {status} | {operations} | {} |\n",
                row.identifier, row.note
            ));
        }
    }
    out
}
