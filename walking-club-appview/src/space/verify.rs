//! Deniable-commit verification + LtHash reconciliation.
//!
//! Wire facts: `commit.{hash,mac,ikm,sig}` arrive base64 (`$bytes`,
//! STANDARD_NO_PAD); `setHash` arrives hex of the full 2048-byte LtHash state.
//! Reconcile is `sha256(hex_decode(setHash)) == base64_decode(commit.hash)`,
//! i.e. `LtHash::from_state_bytes(hex_decode(setHash)).digest() == commit.hash`.

use atproto_identity::key::KeyData;
use atproto_space::{
    Commit, LtHash, SetHash, SpaceContext, verify_commit, verify_commit_signature,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64_NOPAD;

use crate::error::{AppError, AppResult};

/// Decode a commit's `$bytes` byte fields from their base64 wire form.
pub fn decode_commit_bytes(b64: &str) -> AppResult<Vec<u8>> {
    BASE64_NOPAD
        .decode(b64)
        .map_err(|e| AppError::Space(format!("invalid commit $bytes: {e}")))
}

/// Reconstruct an `LtHash` from the hex-encoded 2048-byte state.
pub fn lthash_from_set_hash_hex(set_hash_hex: &str) -> AppResult<LtHash> {
    let state = hex::decode(set_hash_hex)
        .map_err(|e| AppError::Space(format!("invalid setHash hex: {e}")))?;
    LtHash::from_state_bytes(&state)
        .map_err(|e| AppError::Space(format!("invalid LtHash state: {e}")))
}

/// Verify a deniable commit (MAC bind) and its signature, then reconcile the
/// `setHash` against `commit.hash`.
pub fn verify_repo_state(
    context: &SpaceContext,
    commit: &Commit,
    author_key: &KeyData,
    set_hash_hex: &str,
) -> AppResult<()> {
    verify_commit(context, commit).map_err(|e| AppError::Space(format!("commit verify: {e}")))?;
    verify_commit_signature(context, commit, author_key)
        .map_err(|e| AppError::Space(format!("commit sig: {e}")))?;
    let lt = lthash_from_set_hash_hex(set_hash_hex)?;
    if lt.digest() != commit.hash {
        return Err(AppError::Space(
            "setHash/commit.hash reconcile mismatch".into(),
        ));
    }
    Ok(())
}
