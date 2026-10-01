//! NumericDate parsing, exact arithmetic, and deterministic clock boundaries.

use jose_rs::{
    jwt::{Claims, NumericDate, Validation},
    JoseError, JoseHeader,
};

fn date(s: &str) -> NumericDate {
    s.parse().unwrap()
}
fn claims(s: &str) -> Claims {
    serde_json::from_str(s).unwrap()
}

#[test]
fn preserves_integer_fractional_and_scientific_values() {
    for (input, output) in [
        ("1812467163", "1812467163"),
        ("1812467163.592736", "1812467163.592736"),
        ("1.812467163592736e9", "1812467163.592736"),
        ("0.000000001", "0.000000001"),
        ("1e-9", "0.000000001"),
        ("1.000000000000", "1"),
        ("1.5e3", "1500"),
        ("2e0", "2"),
        ("0e-999", "0"),
        (
            "18446744073709551615.999999999",
            "18446744073709551615.999999999",
        ),
        ("9007199254740993.123456789", "9007199254740993.123456789"),
    ] {
        let parsed = date(input);
        assert_eq!(serde_json::to_string(&parsed).unwrap(), output);
        assert_eq!(serde_json::from_str::<NumericDate>(output).unwrap(), parsed);
        for field in ["exp", "nbf", "iat"] {
            let raw = format!(r#"{{"{field}":{input}}}"#);
            let parsed = claims(&raw);
            assert_eq!(
                serde_json::to_string(&parsed).unwrap(),
                format!(r#"{{"{field}":{output}}}"#)
            );
        }
    }
    assert_eq!(date("1.25").as_secs(), 1);
    assert_eq!(date("1.25").subsec_nanos(), 250_000_000);
    assert_eq!(
        NumericDate::from(std::time::Duration::new(1, 250_000_000)),
        date("1.25")
    );
}

#[test]
fn rejects_invalid_out_of_range_and_subnanosecond_values() {
    for raw in [
        "-1",
        "-0.1",
        "-0",
        "18446744073709551616",
        "18446744073709551616.0",
        "1e100",
        "1e2147483648",
        "1e-2147483648",
        "0.0000000001",
        "1.0000000001",
        "true",
        "false",
        "\"1\"",
        "[]",
        "{}",
        "NaN",
        "Infinity",
    ] {
        assert!(raw.parse::<NumericDate>().is_err(), "{raw}");
        for field in ["exp", "nbf", "iat"] {
            assert!(
                serde_json::from_str::<Claims>(&format!(r#"{{"{field}":{raw}}}"#)).is_err(),
                "{field}: {raw}"
            );
        }
    }
    let overlong = format!("1.{}", "0".repeat(127));
    assert!(overlong.parse::<NumericDate>().is_err());
    assert!(serde_json::from_str::<Claims>(&format!(r#"{{"exp":{overlong}}}"#)).is_err());
    assert!(NumericDate::new(0, 1_000_000_000).is_err());
}

#[test]
fn absent_and_null_dates_keep_existing_presence_rules() {
    for raw in ["{}", r#"{"exp":null,"nbf":null,"iat":null}"#] {
        let c = claims(raw);
        assert!(c.exp.is_none() && c.nbf.is_none() && c.iat.is_none());
        assert!(Validation::new().validate_at(&c, None, date("10")).is_ok());
        for v in [
            Validation::new().require_exp(),
            Validation::new().require_nbf(),
            Validation::new().require_iat(),
            Validation::new().with_max_age(10),
        ] {
            assert!(v.validate_at(&c, None, date("10")).is_err());
        }
    }
}

#[test]
fn expiration_is_exclusive_with_and_without_leeway() {
    let c = claims(r#"{"exp":10.5}"#);
    for (leeway, before, at, after) in [
        (0, "10.499999999", "10.5", "10.500000001"),
        (2, "12.499999999", "12.5", "12.500000001"),
    ] {
        let v = Validation::new().with_leeway(leeway);
        assert!(v.validate_at(&c, None, date(before)).is_ok());
        for now in [at, after] {
            assert!(matches!(
                v.validate_at(&c, None, date(now)),
                Err(JoseError::Expired)
            ));
        }
    }
    assert!(matches!(
        Validation::new()
            .with_leeway(0)
            .validate_at(&claims(r#"{"exp":10}"#), None, date("10")),
        Err(JoseError::Expired)
    ));
}

#[test]
fn not_before_and_future_iat_keep_fractional_boundaries() {
    for field in ["nbf", "iat"] {
        let c = claims(&format!(r#"{{"{field}":10.5}}"#));
        for (leeway, before, at) in [(0, "10.499999999", "10.5"), (2, "8.499999999", "8.5")] {
            let v = Validation::new().with_leeway(leeway);
            assert!(v.validate_at(&c, None, date(before)).is_err());
            assert!(v.validate_at(&c, None, date(at)).is_ok());
            assert!(v.validate_at(&c, None, date("10.500000001")).is_ok());
        }
    }
}

#[test]
fn max_age_is_inclusive_and_preserves_fraction() {
    let c = claims(r#"{"iat":10.5}"#);
    for (leeway, at, after) in [(0, "12.5", "12.500000001"), (3, "15.5", "15.500000001")] {
        let v = Validation::new().with_max_age(2).with_leeway(leeway);
        assert!(v.validate_at(&c, None, date(at)).is_ok());
        assert!(matches!(
            v.validate_at(&c, None, date(after)),
            Err(JoseError::Expired)
        ));
    }
}

#[test]
fn arithmetic_does_not_wrap_and_header_policy_is_retained() {
    let c = claims(r#"{"exp":18446744073709551615.999999999,"iat":0.5}"#);
    let v = Validation::new()
        .with_leeway(u64::MAX)
        .with_max_age(u64::MAX);
    assert!(v
        .validate_at(&c, None, date("18446744073709551615.999999999"))
        .is_ok());
    let v = Validation::new().with_typ("at+jwt");
    assert!(v
        .validate_at(
            &Claims::default(),
            Some(&JoseHeader::jwt("HS256")),
            date("1")
        )
        .is_err());
    let v = Validation::new().with_allowed_algorithms(vec![jose_rs::JwsAlgorithm::HS512]);
    assert!(v
        .validate_at(
            &Claims::default(),
            Some(&JoseHeader::jwt("HS256")),
            date("1")
        )
        .is_err());
}

#[test]
fn signed_claims_preserve_fractional_dates() {
    let key = jose_rs::jwk::generate_symmetric_for_alg("HS256").unwrap();
    let c = claims(r#"{"exp":4102444800.123456789,"iat":1.25,"nbf":0.000000001}"#);
    let token = jose_rs::jwt::encode_with_jwk(&key, &JoseHeader::jwt("HS256"), &c).unwrap();
    let decoded = jose_rs::jwt::decode_with_jwk(&key, &token, &Validation::new()).unwrap();
    assert_eq!(decoded.exp, c.exp);
    assert_eq!(decoded.nbf, c.nbf);
    assert_eq!(decoded.iat, c.iat);
}

#[test]
fn ordinary_json_value_adapters_remain_supported() {
    let c: Claims = serde_json::from_value(serde_json::json!({"exp": 10.5})).unwrap();
    assert_eq!(c.exp, Some(date("10.5")));
    assert_eq!(
        serde_json::to_value(c).unwrap(),
        serde_json::json!({"exp": 10.5})
    );
}
