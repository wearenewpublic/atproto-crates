//! Datetime syntax validation
//!
//! Validates datetime strings according to the AT Protocol specification,
//! which requires a subset of RFC 3339 / ISO 8601 datetime format.

use std::sync::LazyLock;

use regex::Regex;

use chrono::{DateTime, Datelike};

use crate::validation::data_errors::DataValidationError;
use crate::validation::flags::ValidateFlags;

/// Longest datetime this format accepts, matching the reference.
const MAX_LEN: usize = 64;

/// A `YYYY` field can represent 0000 through 9999 and nothing else.
const MIN_YEAR: i32 = 0;
const MAX_YEAR: i32 = 9999;

fn invalid(value: &str, reason: impl Into<String>) -> DataValidationError {
    DataValidationError::StringFormatInvalid {
        format: "datetime".to_string(),
        value: value.to_string(),
        reason: reason.into(),
    }
}

/// Strict RFC 3339 datetime regex
///
/// Format: YYYY-MM-DDTHH:MM:SS[.fractional]Z or YYYY-MM-DDTHH:MM:SS[.fractional]+HH:MM
static STRICT_DATETIME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$"
    ).expect("strict datetime regex should compile")
});

/// Lenient datetime regex that also accepts lowercase 't' and 'z', space separator, etc.
static LENIENT_DATETIME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:?[0-9]{2})$"
    ).expect("lenient datetime regex should compile")
});

/// Validate a datetime string
///
/// With strict validation, requires RFC 3339 format with uppercase T and Z.
/// With lenient validation (via `ValidateFlags::ALLOW_LENIENT_DATETIME`),
/// accepts more datetime formats.
pub fn validate_datetime(value: &str, flags: ValidateFlags) -> Result<(), DataValidationError> {
    if value.is_empty() {
        return Err(invalid(value, "datetime cannot be empty"));
    }

    // Cheap bounds first, so a pathological string never reaches the parser.
    if value.len() > MAX_LEN {
        return Err(invalid(value, "datetime is too long (64 characters max)"));
    }

    // RFC 3339 §4.3 gives `-00:00` a meaning of its own — "the offset to local
    // time is unknown" — rather than making it a spelling of UTC. A timestamp
    // that declines to say where it came from is not what this format is for,
    // and both reference implementations refuse it by name.
    if value.ends_with("-00:00") {
        return Err(invalid(
            value,
            r#"datetime must not use "-00:00"; use "Z" or "+00:00""#,
        ));
    }

    let is_valid = if flags.contains(ValidateFlags::ALLOW_LENIENT_DATETIME) {
        LENIENT_DATETIME_REGEX.is_match(value)
    } else {
        STRICT_DATETIME_REGEX.is_match(value)
    };

    if !is_valid {
        return Err(invalid(
            value,
            "datetime must be a valid RFC 3339 datetime string",
        ));
    }

    // The shape is right; now the calendar.
    //
    // This replaces per-field range checks, which could only ask whether each
    // number was individually plausible. `2023-02-30` has a month in 1..=12 and
    // a day in 1..=31 and is still not a date. Parsing asks the question the
    // ranges were approximating.
    let canonical = canonicalize(value);
    let parsed = DateTime::parse_from_rfc3339(&canonical)
        .map_err(|e| invalid(value, format!("datetime did not parse: {e}")))?;

    // The year is checked *after* the offset is applied, because the offset can
    // move it. `0000-01-01T00:00:00+01:00` is a well-formed string naming an
    // instant in year -1, which no `YYYY` field can represent — so a value that
    // looks in range is out of range once it means anything.
    let year = parsed.naive_utc().year();
    if !(MIN_YEAR..=MAX_YEAR).contains(&year) {
        return Err(invalid(
            value,
            format!("datetime normalizes to year {year}, outside 0000-9999"),
        ));
    }

    Ok(())
}

/// Rewrite a lenient datetime into the strict spelling so one parser handles
/// both.
///
/// The strict form is already canonical, so this is a no-op for it. For the
/// lenient form it uppercases the `t`/`z` markers, replaces a space separator,
/// and inserts the colon in a `+hhmm` offset — the three ways
/// [`LENIENT_DATETIME_REGEX`] differs from [`STRICT_DATETIME_REGEX`]. Doing it
/// here means the calendar and range checks above apply to lenient values too,
/// rather than lenient meaning "unchecked".
fn canonicalize(value: &str) -> String {
    let mut out: String = value
        .char_indices()
        .map(|(i, c)| match c {
            't' | ' ' if i == 10 => 'T',
            'z' => 'Z',
            other => other,
        })
        .collect();

    // `+hhmm` -> `+hh:mm`. Only the trailing five characters can be an offset
    // without a colon; `Z` and `+hh:mm` endings are left alone.
    if out.len() >= 5 {
        let tail = &out[out.len() - 5..];
        let bytes = tail.as_bytes();
        if (bytes[0] == b'+' || bytes[0] == b'-') && bytes[1..].iter().all(u8::is_ascii_digit) {
            let (head, off) = out.split_at(out.len() - 5);
            out = format!("{head}{}{}:{}", &off[..1], &off[1..3], &off[3..]);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_datetimes_strict() {
        let valid = [
            "2023-01-01T00:00:00Z",
            "2023-12-31T23:59:59Z",
            "2023-06-15T12:30:45.123Z",
            "2023-06-15T12:30:45.123456789Z",
            "2023-06-15T12:30:45+05:30",
            "2023-06-15T12:30:45-08:00",
            "2023-06-15T12:30:45.000Z",
        ];
        let flags = ValidateFlags::empty();
        for dt in valid {
            assert!(
                validate_datetime(dt, flags).is_ok(),
                "should be valid: {}",
                dt
            );
        }
    }

    #[test]
    fn test_invalid_datetimes_strict() {
        let invalid = [
            "",
            "2023-01-01",
            "not-a-datetime",
            "2023-13-01T00:00:00Z",
            "2023-01-32T00:00:00Z",
            "2023-01-01T25:00:00Z",
        ];
        let flags = ValidateFlags::empty();
        for dt in invalid {
            assert!(
                validate_datetime(dt, flags).is_err(),
                "should be invalid: {}",
                dt
            );
        }
    }

    #[test]
    fn test_lenient_datetimes() {
        let flags = ValidateFlags::ALLOW_LENIENT_DATETIME;
        assert!(validate_datetime("2023-01-01T00:00:00Z", flags).is_ok());
        assert!(validate_datetime("2023-01-01t00:00:00z", flags).is_ok());
        assert!(validate_datetime("2023-01-01T00:00:00+0000", flags).is_ok());
    }
}

#[cfg(test)]
mod interop_rules {
    use super::*;

    /// `-00:00` means "offset unknown" (RFC 3339 §4.3), not UTC.
    #[test]
    fn negative_zero_offset_is_refused() {
        assert!(
            validate_datetime("1985-04-12T23:20:50.123-00:00", ValidateFlags::empty()).is_err()
        );
        // The spellings that do mean UTC are unaffected.
        assert!(validate_datetime("1985-04-12T23:20:50.123Z", ValidateFlags::empty()).is_ok());
        assert!(validate_datetime("1985-04-12T23:20:50.123+00:00", ValidateFlags::empty()).is_ok());
    }

    /// The year is checked after the offset is applied.
    ///
    /// `0000-01-01T00:00:00+01:00` has a `YYYY` field in range and names an
    /// instant in year -1. Checking the literal field would have accepted it.
    #[test]
    fn the_year_is_checked_after_normalization() {
        assert!(validate_datetime("0000-01-01T00:00:00+01:00", ValidateFlags::empty()).is_err());
        assert!(validate_datetime("9999-12-31T23:59:00-00:01", ValidateFlags::empty()).is_err());
        // Same instants, in range once normalized.
        assert!(validate_datetime("0000-01-01T00:00:00Z", ValidateFlags::empty()).is_ok());
        assert!(validate_datetime("9999-12-31T23:59:00Z", ValidateFlags::empty()).is_ok());
    }

    /// Parsing replaces per-field range checks, which could only ask whether
    /// each number was individually plausible.
    ///
    /// `2023-02-30` has a month in 1..=12 and a day in 1..=31, and is not a
    /// date. The previous checks accepted it.
    #[test]
    fn impossible_calendar_dates_are_refused() {
        for value in [
            "2023-02-30T00:00:00Z",
            "2023-04-31T00:00:00Z",
            "2023-02-29T00:00:00Z", // 2023 is not a leap year
        ] {
            assert!(
                validate_datetime(value, ValidateFlags::empty()).is_err(),
                "should be invalid: {value}"
            );
        }
        assert!(validate_datetime("2024-02-29T00:00:00Z", ValidateFlags::empty()).is_ok());
    }

    /// A leap second is a real time and stays valid.
    #[test]
    fn leap_seconds_are_accepted() {
        assert!(validate_datetime("1990-12-31T23:59:60Z", ValidateFlags::empty()).is_ok());
        assert!(validate_datetime("1990-12-31T15:59:60-08:00", ValidateFlags::empty()).is_ok());
    }

    /// The lenient flag still admits the legacy spellings, and now gets the
    /// calendar checks too.
    ///
    /// Lenient means "accepts more shapes", not "checks less" — otherwise the
    /// flag would be a way to write an impossible date into a record.
    #[test]
    fn lenient_mode_widens_the_shape_without_dropping_the_calendar() {
        let lenient = ValidateFlags::ALLOW_LENIENT_DATETIME;
        for value in [
            "1985-04-12t23:20:50.123Z",
            "1985-04-12T23:20:50.123z",
            "1985-04-12 23:20:50.123Z",
            "1985-04-12T23:20:50.123+0100",
        ] {
            assert!(
                validate_datetime(value, lenient).is_ok(),
                "lenient should accept: {value}"
            );
            assert!(
                validate_datetime(value, ValidateFlags::empty()).is_err(),
                "strict should refuse: {value}"
            );
        }
        assert!(validate_datetime("2023-02-30t00:00:00z", lenient).is_err());
    }
}
