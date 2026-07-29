//! Structural checks applied to every record before it is written.
//!
//! These are the schema-free checks: they need no lexicon, only the grammars
//! the protocol defines for a record key, an NSID, and the `$type` field.
//!
//! They matter because the repository is append-only. A record key containing
//! `/` lands at an MST path that does not match its own AT-URI, and a record
//! stored without `$type` cannot be decoded by any consumer — and by the time
//! either is noticed, the commit is signed and sequenced. Neither is
//! recoverable.
//!
//! The validators themselves already existed in `atproto-lexicon`, which this
//! crate has always depended on. Nothing in the PDS called them.
//!
//! # `$type` is supplied, not required
//!
//! A record arriving with no `$type` gets one equal to its collection, which is
//! what `repo/prepare.ts:167-178` in the reference does. Rejecting it would
//! refuse writes the reference accepts. A `$type` that *disagrees* with the
//! collection is refused, because there is no reading under which that is what
//! the caller meant.

use crate::errors::{PdsError, PdsResult};
use serde_json::Value;

/// What the caller asked for on the `validate` flag.
///
/// The lexicon: *"Can be set to 'false' to skip Lexicon schema validation of
/// record data, 'true' to require it, or leave unset to validate only for known
/// Lexicons."* Three states, not two — which is why this is not a `bool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValidateMode {
    /// Unset — validate against known lexicons only.
    #[default]
    KnownOnly,
    /// `true` — schema validation is required.
    Required,
    /// `false` — skip schema validation.
    Skipped,
}

impl ValidateMode {
    /// Read the flag as it arrived on the wire.
    #[must_use]
    pub fn from_flag(flag: Option<bool>) -> Self {
        match flag {
            None => ValidateMode::KnownOnly,
            Some(true) => ValidateMode::Required,
            Some(false) => ValidateMode::Skipped,
        }
    }

    /// The `validationStatus` this write should report.
    ///
    /// Always `unknown` today: schema validation is not implemented, so no
    /// record can be reported as `valid` without lying. The lexicon's
    /// `knownValues` are `valid` and `unknown`, and `unknown` is the honest
    /// one until the schema engine is wired.
    #[must_use]
    pub fn status(self) -> Option<&'static str> {
        match self {
            ValidateMode::Skipped => None,
            _ => Some("unknown"),
        }
    }

    /// Refuse a request that requires validation this build cannot perform.
    ///
    /// Accepting `validate: true` and doing nothing is the failure mode this
    /// codebase keeps producing: a control that reads as working and is not.
    /// A caller who explicitly asked for validation is better served by an
    /// error naming the gap than by a success that did not validate anything.
    ///
    /// # Errors
    ///
    /// [`PdsError::ValidationUnavailable`] when the caller passed
    /// `validate: true`.
    pub fn ensure_supported(self) -> PdsResult<()> {
        if self == ValidateMode::Required {
            return Err(PdsError::ValidationUnavailable);
        }
        Ok(())
    }
}

/// Check a collection NSID.
///
/// # Errors
///
/// [`PdsError::InvalidRecord`] when the NSID does not parse.
pub fn check_collection(collection: &str) -> PdsResult<()> {
    atproto_lexicon::validation::syntax::validate_nsid(collection).map_err(|e| {
        PdsError::InvalidRecord {
            reason: format!("collection {collection} is not a valid NSID: {e}"),
        }
    })
}

/// Check a record key against the record-key grammar.
///
/// 1–512 characters from `[A-Za-z0-9.:_~-]`, and never `.` or `..`. The
/// character set is what keeps the key a legal MST path segment and a legal
/// URI path component at the same time — which is why a key containing `/` is
/// not merely untidy but produces a record whose MST path and AT-URI disagree.
///
/// # Errors
///
/// [`PdsError::InvalidRecord`] when the key is outside the grammar.
pub fn check_rkey(rkey: &str) -> PdsResult<()> {
    atproto_lexicon::validation::syntax::validate_record_key(rkey).map_err(|e| {
        PdsError::InvalidRecord {
            reason: format!("record key {rkey:?} is not valid: {e}"),
        }
    })
}

/// Reconcile a record's `$type` with the collection it is being written to.
///
/// Returns the value to store: unchanged when `$type` already matches, with
/// `$type` inserted when it was absent.
///
/// # Errors
///
/// [`PdsError::InvalidRecord`] when the record is not a JSON object, or when
/// its `$type` disagrees with `collection`.
pub fn reconcile_type(collection: &str, value: Value) -> PdsResult<Value> {
    let Value::Object(mut map) = value else {
        return Err(PdsError::InvalidRecord {
            reason: "record must be a JSON object".to_string(),
        });
    };
    match map.get("$type") {
        None => {
            map.insert("$type".to_string(), Value::String(collection.to_string()));
        }
        Some(Value::String(t)) if t == collection => {}
        Some(Value::String(t)) => {
            return Err(PdsError::InvalidRecord {
                reason: format!("record $type is {t}, expected {collection}"),
            });
        }
        Some(_) => {
            return Err(PdsError::InvalidRecord {
                reason: "record $type must be a string".to_string(),
            });
        }
    }
    Ok(Value::Object(map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_key_outside_the_grammar_is_refused() {
        // The `/` case is the one that cannot be undone: the record lands at an
        // MST path that does not match its own AT-URI.
        for bad in [
            "with/slash",
            "with space",
            ".",
            "..",
            "",
            "with\nnewline",
            "with?query",
            "with#fragment",
        ] {
            assert!(check_rkey(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn the_keys_the_protocol_allows_are_accepted() {
        // Known-answer against the record-key spec's character set. A test that
        // only checked rejections would pass against a function refusing
        // everything.
        for good in [
            "3jui7kp54ic2i", // a TID, the common case
            "self",          // the singleton key
            "a",             // one character is the minimum
            "with.dots",
            "with-dash",
            "with_underscore",
            "with~tilde",
            "with:colon",
            "MiXeDcAsE123",
        ] {
            assert!(check_rkey(good).is_ok(), "{good:?} should be accepted");
        }
        // 512 is the ceiling, and it is inclusive.
        assert!(check_rkey(&"a".repeat(512)).is_ok());
        assert!(check_rkey(&"a".repeat(513)).is_err());
    }

    #[test]
    fn a_collection_must_be_an_nsid() {
        assert!(check_collection("app.bsky.feed.post").is_ok());
        assert!(check_collection("com.atproto.lexicon.schema").is_ok());
        for bad in ["notannsid", "two.parts", "", "app.bsky."] {
            assert!(check_collection(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn an_absent_type_is_supplied_from_the_collection() {
        // The reference fills it in rather than refusing. A record stored
        // without `$type` is undecodable by every consumer, and supplying it is
        // what makes the record decodable — refusing would only refuse writes
        // the reference accepts.
        let out = reconcile_type("app.bsky.feed.post", json!({"text": "hi"})).unwrap();
        assert_eq!(out["$type"], "app.bsky.feed.post");
        assert_eq!(out["text"], "hi");
    }

    #[test]
    fn a_matching_type_is_left_alone() {
        let input = json!({"$type": "app.bsky.feed.post", "text": "hi"});
        let out = reconcile_type("app.bsky.feed.post", input.clone()).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn a_disagreeing_type_is_refused() {
        // No reading under which this is what the caller meant.
        let err = reconcile_type(
            "app.bsky.feed.post",
            json!({"$type": "app.bsky.feed.like", "text": "hi"}),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("app.bsky.feed.like"), "{err}");
    }

    #[test]
    fn a_non_object_record_is_refused() {
        for bad in [json!("a string"), json!([1, 2, 3]), json!(42), json!(null)] {
            assert!(reconcile_type("app.bsky.feed.post", bad).is_err());
        }
        // And a `$type` that is not a string.
        assert!(reconcile_type("app.bsky.feed.post", json!({"$type": 1})).is_err());
    }

    #[test]
    fn the_validate_flag_has_three_states() {
        assert_eq!(ValidateMode::from_flag(None), ValidateMode::KnownOnly);
        assert_eq!(ValidateMode::from_flag(Some(true)), ValidateMode::Required);
        assert_eq!(ValidateMode::from_flag(Some(false)), ValidateMode::Skipped);

        // Only the explicit `true` is refused. Accepting it and validating
        // nothing would be a control that reads as working and is not.
        assert!(ValidateMode::KnownOnly.ensure_supported().is_ok());
        assert!(ValidateMode::Skipped.ensure_supported().is_ok());
        assert!(ValidateMode::Required.ensure_supported().is_err());

        // `unknown` is the honest status while no schema engine is wired;
        // a skipped validation reports nothing at all.
        assert_eq!(ValidateMode::KnownOnly.status(), Some("unknown"));
        assert_eq!(ValidateMode::Skipped.status(), None);
    }
}
