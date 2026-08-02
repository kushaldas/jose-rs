#![cfg(feature = "post-quantum")]

use jose_rs::jwk::{generate_composite_mldsa, jwk_to_software_key, software_key_to_jwk, Jwk};
use jose_rs::{base64url, jws, JoseHeader, JwsAlgorithm};
use kryptering::CompositeMlDsaVariant as Variant;
use serde::Deserialize;

const DRAFT: &str = include_str!("../rfcs/draft-ietf-jose-pq-composite-sigs-03.txt");
const PAYLOAD: &[u8] = b"It's a dangerous business, Frodo, going out your door.";

#[derive(Deserialize)]
struct DraftJoseVector {
    jwk: Jwk,
    jws: String,
}

fn variant(name: &str) -> Variant {
    match name {
        "ML-DSA-44-ES256" => Variant::MlDsa44Es256,
        "ML-DSA-65-ES256" => Variant::MlDsa65Es256,
        "ML-DSA-87-ES384" => Variant::MlDsa87Es384,
        "ML-DSA-44-Ed25519" => Variant::MlDsa44Ed25519,
        "ML-DSA-65-Ed25519" => Variant::MlDsa65Ed25519,
        "ML-DSA-87-Ed448" => Variant::MlDsa87Ed448,
        other => panic!("unexpected draft algorithm: {other}"),
    }
}

fn jose_vectors() -> Vec<DraftJoseVector> {
    let section = DRAFT
        .rsplit_once("A.1.  JOSE")
        .expect("JOSE appendix")
        .1
        .split_once("A.2.  COSE")
        .expect("COSE appendix")
        .0;
    let marker = "{\n  \"mldsa_seed\"";
    let mut remaining = section;
    let mut vectors = Vec::new();

    while let Some(offset) = remaining.find(marker) {
        let object = &remaining[offset..];
        let mut depth = 0usize;
        let mut end = None;
        for (index, byte) in object.bytes().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(index + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.expect("complete appendix JSON object");
        vectors.push(serde_json::from_str(&object[..end]).expect("valid appendix JSON"));
        remaining = &object[end..];
    }

    assert_eq!(vectors.len(), 6, "all six JOSE examples must be found");
    vectors
}

fn with_large_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name("composite-jose-test".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn appendix_a_jose_vectors_verify_and_roundtrip() {
    with_large_stack(|| {
        for vector in jose_vectors() {
            let algorithm = vector.jwk.alg.as_deref().expect("AKP alg");
            let variant = variant(algorithm);

            assert_eq!(vector.jwk.kty, "AKP");
            assert_eq!(
                base64url::decode(vector.jwk.pub_.as_deref().expect("pub"))
                    .unwrap()
                    .len(),
                variant.public_key_len()
            );
            assert_eq!(
                base64url::decode(vector.jwk.priv_.as_deref().expect("priv"))
                    .unwrap()
                    .len(),
                variant.private_key_len()
            );
            assert_eq!(
                JwsAlgorithm::from_str(algorithm)
                    .unwrap()
                    .to_crypto()
                    .unwrap(),
                kryptering::SignatureAlgorithm::CompositeMlDsa(variant)
            );

            let signature = vector.jws.rsplit('.').next().expect("signature segment");
            assert_eq!(
                base64url::decode(signature).unwrap().len(),
                variant.signature_len()
            );

            let public_jwk = vector.jwk.to_public_jwk();
            assert_eq!(
                jws::compact::verify_with_jwk(&public_jwk, &vector.jws).unwrap(),
                PAYLOAD
            );
            assert_eq!(
                jose_rs::jwk::thumbprint::thumbprint_sha256(&public_jwk).unwrap(),
                vector.jwk.kid.as_deref().expect("thumbprint kid")
            );

            let key = jwk_to_software_key(&vector.jwk).unwrap();
            assert_eq!(
                key.algorithm(),
                kryptering::KeyAlgorithm::CompositeMlDsa(variant)
            );
            assert!(key.has_private_key());
            let roundtripped = software_key_to_jwk(&key).unwrap();
            assert_eq!(roundtripped.alg, vector.jwk.alg);
            assert_eq!(roundtripped.pub_, vector.jwk.pub_);
            assert_eq!(roundtripped.priv_, vector.jwk.priv_);
        }
    });
}

#[test]
fn generated_composite_jwks_sign_and_verify_for_every_variant() {
    with_large_stack(|| {
        for variant in Variant::ALL {
            let private_jwk = generate_composite_mldsa(variant).unwrap();
            let public_jwk = private_jwk.to_public_jwk();
            let header = JoseHeader::new(variant.name());
            let token = jws::compact::sign_with_jwk(&private_jwk, PAYLOAD, &header).unwrap();

            assert_eq!(
                jws::compact::verify_with_jwk(&public_jwk, &token).unwrap(),
                PAYLOAD
            );
            assert!(public_jwk.priv_.is_none());
            assert_eq!(
                base64url::decode(public_jwk.pub_.as_deref().unwrap())
                    .unwrap()
                    .len(),
                variant.public_key_len()
            );
            assert_eq!(
                base64url::decode(token.rsplit('.').next().unwrap())
                    .unwrap()
                    .len(),
                variant.signature_len()
            );
        }
    });
}

#[test]
fn composite_flattened_and_general_jws_preserve_certificate_binding() {
    with_large_stack(|| {
        let variant = Variant::MlDsa44Ed25519;
        let private_jwk = generate_composite_mldsa(variant).unwrap();
        let public_jwk = private_jwk.to_public_jwk();
        let algorithm = JwsAlgorithm::MlDsa44Ed25519.to_crypto().unwrap();
        let signer =
            kryptering::SoftwareSigner::new(algorithm, jwk_to_software_key(&private_jwk).unwrap())
                .unwrap();
        let verifier =
            kryptering::SoftwareVerifier::new(algorithm, jwk_to_software_key(&public_jwk).unwrap())
                .unwrap();

        let certificate = b"test composite certificate DER";
        let mut header = JoseHeader::for_alg(JwsAlgorithm::MlDsa44Ed25519);
        jws::x5::bind_cert_to_header(&mut header, certificate);

        let flattened = jws::json::sign_flattened(&signer, PAYLOAD, &header).unwrap();
        assert_eq!(
            jws::json::verify_flattened(&verifier, &flattened).unwrap(),
            PAYLOAD
        );
        let protected: JoseHeader =
            serde_json::from_slice(&base64url::decode(&flattened.protected).unwrap()).unwrap();
        jws::x5::verify_cert_binding(&protected, certificate).unwrap();

        let general = jws::json::sign_general(&[(&signer, &header)], PAYLOAD).unwrap();
        assert_eq!(
            jws::json::verify_general(&verifier, &general).unwrap(),
            PAYLOAD
        );
    });
}

#[test]
fn composite_jws_rejects_tampering_algorithm_confusion_and_bad_keys() {
    with_large_stack(|| {
        let mut vectors = jose_vectors();
        let vector = vectors.remove(0);
        let public_jwk = vector.jwk.to_public_jwk();

        let mut parts: Vec<String> = vector.jws.split('.').map(str::to_owned).collect();
        let mut signature = base64url::decode(&parts[2]).unwrap();
        signature[0] ^= 1;
        parts[2] = base64url::encode(&signature);
        let tampered = parts.join(".");
        assert!(jws::compact::verify_with_jwk(&public_jwk, &tampered).is_err());

        let mut wrong_algorithm = public_jwk.clone();
        wrong_algorithm.alg = Some("ML-DSA-44-Ed25519".into());
        let error = jws::compact::verify_with_jwk(&wrong_algorithm, &vector.jws)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match token header alg"));

        let mut short_public = public_jwk.clone();
        let mut public = base64url::decode(short_public.pub_.as_deref().unwrap()).unwrap();
        public.pop();
        short_public.pub_ = Some(base64url::encode(&public));
        assert!(jwk_to_software_key(&short_public).is_err());

        let mut short_private = vector.jwk;
        let mut private = base64url::decode(short_private.priv_.as_deref().unwrap()).unwrap();
        private.pop();
        short_private.priv_ = Some(base64url::encode(&private));
        assert!(jwk_to_software_key(&short_private).is_err());
    });
}
