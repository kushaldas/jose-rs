//! JWT Claims Set (RFC 7519 Section 4).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JWT Claims Set (RFC 7519 Section 4).
///
/// Registered claims are typed fields; custom claims go in `extra`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer (`iss`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Subject (`sub`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Audience (`aud`) — can be a single string or array of strings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,

    /// Expiration Time (`exp`) — NumericDate (seconds since epoch)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_opt_numericdate"
    )]
    pub exp: Option<u64>,

    /// Not Before (`nbf`) — NumericDate
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_opt_numericdate"
    )]
    pub nbf: Option<u64>,

    /// Issued At (`iat`) — NumericDate
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_opt_numericdate"
    )]
    pub iat: Option<u64>,

    /// JWT ID (`jti`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Custom claims
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, Value>,
}

/// Deserialize an optional NumericDate (`exp`/`nbf`/`iat`).
///
/// RFC 7519 §2 defines NumericDate as a JSON number of seconds since the epoch
/// that "is not restricted to integer values" — fractional seconds are legal.
/// Some federation implementations emit timestamps such as `1812467163.592736`.
/// We accept any non-negative finite number and truncate to whole seconds (the
/// sub-second part is not significant for `exp`/`nbf`/`iat` validation).
fn de_opt_numericdate<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    match Option::<serde_json::Number>::deserialize(deserializer)? {
        None => Ok(None),
        Some(n) => parse_numericdate(&n).map(Some).map_err(D::Error::custom),
    }
}

fn parse_numericdate(number: &serde_json::Number) -> std::result::Result<u64, String> {
    if let Some(value) = number.as_u64() {
        return Ok(value);
    }

    if let Some(value) = number.as_i64() {
        return u64::try_from(value).map_err(|_| format!("invalid NumericDate: {number}"));
    }

    if let Some(value) = number.as_f64() {
        if !value.is_finite() || value < 0.0 {
            return Err(format!("invalid NumericDate: {number}"));
        }

        if value == 0.0 {
            return Ok(0);
        }
    }

    // Parse the original decimal representation so we can floor fractional
    // seconds without the saturation and precision loss of `f64 as u64`.
    parse_decimal_floor_to_u64(&number.to_string())
        .ok_or_else(|| format!("invalid NumericDate: {number}"))
}

fn parse_decimal_floor_to_u64(text: &str) -> Option<u64> {
    let (mantissa, exponent) = text
        .split_once('e')
        .or_else(|| text.split_once('E'))
        .map_or(Some((text, 0_i64)), |(mantissa, exponent)| {
            Some((mantissa, exponent.parse::<i64>().ok()?))
        })?;

    let (integer_part, fractional_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if integer_part.is_empty()
        || !integer_part.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional_part.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }

    let digits = format!("{integer_part}{fractional_part}");
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Some(0);
    }

    let scale = exponent.checked_sub(i64::try_from(fractional_part.len()).ok()?)?;
    if scale >= 0 {
        let mut value = parse_u64_digits(digits)?;
        for _ in 0..usize::try_from(scale).ok()? {
            value = value.checked_mul(10)?;
        }
        Some(value)
    } else {
        let shift = usize::try_from(-scale).ok()?;
        if shift >= digits.len() {
            return Some(0);
        }
        parse_u64_digits(&digits[..digits.len() - shift])
    }
}

fn parse_u64_digits(text: &str) -> Option<u64> {
    let mut value = 0_u64;
    for byte in text.bytes() {
        value = value.checked_mul(10)?;
        value = value.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

/// Audience can be a single string or an array of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    /// Check if this audience contains the given value.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Self::Single(s) => s == value,
            Self::Multiple(v) => v.iter().any(|s| s == value),
        }
    }
}

#[cfg(test)]
mod numericdate_tests {
    use super::Claims;

    #[test]
    fn accepts_integer_numericdate() {
        let c: Claims = serde_json::from_str(r#"{"exp":1812467163,"iat":1812466163}"#).unwrap();
        assert_eq!(c.exp, Some(1812467163));
        assert_eq!(c.iat, Some(1812466163));
    }

    #[test]
    fn accepts_fractional_numericdate() {
        // RFC 7519 permits non-integer NumericDate; truncate to whole seconds.
        let c: Claims =
            serde_json::from_str(r#"{"exp":1812467163.592736,"nbf":1812467000.1}"#).unwrap();
        assert_eq!(c.exp, Some(1812467163));
        assert_eq!(c.nbf, Some(1812467000));
    }

    #[test]
    fn accepts_scientific_notation_numericdate() {
        let c: Claims = serde_json::from_str(r#"{"exp":1.5e3,"iat":2e0}"#).unwrap();
        assert_eq!(c.exp, Some(1500));
        assert_eq!(c.iat, Some(2));
    }

    #[test]
    fn missing_dates_are_none() {
        let c: Claims = serde_json::from_str(r#"{"iss":"x"}"#).unwrap();
        assert_eq!(c.exp, None);
        assert_eq!(c.iat, None);
        assert_eq!(c.nbf, None);
    }

    #[test]
    fn rejects_negative_numericdate() {
        assert!(serde_json::from_str::<Claims>(r#"{"exp":-1}"#).is_err());
        assert!(serde_json::from_str::<Claims>(r#"{"nbf":-0.1}"#).is_err());
    }

    #[test]
    fn rejects_out_of_range_numericdate() {
        assert!(serde_json::from_str::<Claims>(r#"{"exp":18446744073709551616}"#).is_err());
        assert!(serde_json::from_str::<Claims>(r#"{"exp":18446744073709551616.0}"#).is_err());
        assert!(serde_json::from_str::<Claims>(r#"{"exp":1e100}"#).is_err());
    }

    #[test]
    fn roundtrip_serializes_as_integer() {
        let c: Claims = serde_json::from_str(r#"{"exp":1812467163.99}"#).unwrap();
        let s = serde_json::to_string(&c).unwrap();
        assert!(s.contains("\"exp\":1812467163"), "got {s}");
    }
}
