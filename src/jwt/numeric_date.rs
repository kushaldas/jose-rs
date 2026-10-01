//! Exact, bounded JWT NumericDate representation.

use crate::error::{JoseError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{str::FromStr, time::Duration};

/// Non-negative seconds since the Unix epoch with nanosecond precision.
///
/// JSON numbers are parsed as decimal text, without an intermediate `f64`.
/// Values exceeding `u64::MAX` seconds plus 999,999,999 nanoseconds, numeric
/// encodings longer than 128 bytes, and nonzero precision below a nanosecond
/// are rejected. Scientific notation and insignificant trailing zeros work.
/// Missing/null optional claims remain absent, as in the previous Claims API.
///
/// ```
/// use jose_rs::jwt::{Claims, NumericDate};
/// let mut claims = Claims::default();
/// claims.exp = Some(123_u64.into());
/// claims.nbf = Some("122.592736".parse::<NumericDate>()?);
/// assert_eq!(claims.nbf.unwrap().subsec_nanos(), 592_736_000);
/// # Ok::<(), jose_rs::JoseError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NumericDate {
    seconds: u64,
    nanos: u32,
}

impl NumericDate {
    /// Construct an exact timestamp; rejects `nanos >= 1_000_000_000`.
    pub fn new(seconds: u64, nanos: u32) -> Result<Self> {
        if nanos >= 1_000_000_000 {
            return Err(JoseError::InvalidClaims(
                "invalid NumericDate nanoseconds".into(),
            ));
        }
        Ok(Self { seconds, nanos })
    }

    /// Whole seconds since the Unix epoch. Fractional seconds are excluded.
    pub fn as_secs(self) -> u64 {
        self.seconds
    }

    /// Fractional nanoseconds, always less than one billion.
    pub fn subsec_nanos(self) -> u32 {
        self.nanos
    }

    pub(crate) fn as_nanos(self) -> u128 {
        u128::from(self.seconds) * 1_000_000_000 + u128::from(self.nanos)
    }

    fn parse_decimal(text: &str) -> Result<Self> {
        let invalid = || {
            JoseError::InvalidClaims("NumericDate must be a non-negative number within the supported range and nanosecond precision".into())
        };
        if text.len() > 128 {
            return Err(invalid());
        }
        let (mantissa, exponent) = match text.split_once(['e', 'E']) {
            Some((m, e)) => (m, e.parse::<i32>().map_err(|_| invalid())?),
            None => (text, 0),
        };
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        if whole.is_empty()
            || !whole
                .bytes()
                .chain(fraction.bytes())
                .all(|b| b.is_ascii_digit())
        {
            return Err(invalid());
        }
        // Count positions in decimal text; never scale an attacker-controlled
        // exponent with an unbounded loop or allocation.
        let decimal_position = whole.len() as i64 + i64::from(exponent);
        let mut total = 0_u128;
        for (index, digit) in whole.bytes().chain(fraction.bytes()).enumerate() {
            if digit == b'0' {
                continue;
            }
            let power = decimal_position - 1 - index as i64 + 9;
            if !(0..=28).contains(&power) {
                return Err(invalid());
            }
            total += u128::from(digit - b'0') * 10_u128.pow(power as u32);
        }
        let seconds = u64::try_from(total / 1_000_000_000).map_err(|_| invalid())?;
        Self::new(seconds, (total % 1_000_000_000) as u32)
    }
}

impl From<u64> for NumericDate {
    fn from(seconds: u64) -> Self {
        Self { seconds, nanos: 0 }
    }
}

impl From<Duration> for NumericDate {
    fn from(value: Duration) -> Self {
        Self {
            seconds: value.as_secs(),
            nanos: value.subsec_nanos(),
        }
    }
}

impl FromStr for NumericDate {
    type Err = JoseError;

    fn from_str(text: &str) -> Result<Self> {
        if text.len() > 128 {
            return Err(JoseError::InvalidClaims(
                "NumericDate encoding exceeds 128 bytes".into(),
            ));
        }
        let raw: Box<serde_json::value::RawValue> = serde_json::from_str(text)?;
        Self::parse_decimal(raw.get())
    }
}

impl<'de> Deserialize<'de> for NumericDate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
        Self::parse_decimal(raw.get()).map_err(serde::de::Error::custom)
    }
}

impl Serialize for NumericDate {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        if self.nanos == 0 {
            return serializer.serialize_u64(self.seconds);
        }
        let fraction = format!("{:09}", self.nanos);
        let text = format!("{}.{}", self.seconds, fraction.trim_end_matches('0'));
        let raw =
            serde_json::value::RawValue::from_string(text).map_err(serde::ser::Error::custom)?;
        raw.serialize(serializer)
    }
}
