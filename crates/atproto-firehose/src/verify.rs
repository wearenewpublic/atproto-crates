//! Verifying a `#commit` against the repository that claims to have made it.
//!
//! Three levels, because the cost is not the same and neither is the claim.
//!
//! [`VerificationLevel::Off`] trusts the relay. That is defensible for a
//! consumer reading from a relay it operates and indefensible for one reading
//! from somebody else's, and the difference is worth naming rather than
//! leaving to whether anyone called a function.
//!
//! [`VerificationLevel::SignatureOnly`] proves that the repository signed
//! *some* commit at this revision, which is what a consumer indexing metadata
//! needs and costs one DID resolution plus one signature check.
//!
//! [`VerificationLevel::Full`] additionally proves that the tree walks from the
//! root the commit signed and that every op describes it truthfully. The
//! second half is the one a consumer forgets: `verify_inductive` never reads
//! `ops[]`, so a commit can pass it while its ops array lies about what
//! changed, and an app view that stops there indexes an unverified claim about
//! a verified tree.

use async_trait::async_trait;
use atproto_dasl::car::CarReader;
use atproto_identity::key::{KeyData, validate};
use atproto_repo::{Commit, verify_inductive, verify_op_inclusion};

use crate::errors::VerifyFailure;
use crate::wire::CommitEnvelope;

/// How much of a commit to prove before acting on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerificationLevel {
    /// Trust the relay. No DID resolution, no signature check, no tree walk.
    Off,
    /// Check the commit signature against the repository's signing key.
    SignatureOnly,
    /// Signature, tree, and every tracked op's inclusion in it.
    #[default]
    Full,
}

/// What a commit proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// Nothing was checked.
    Skipped,
    /// The repository signed a commit at this revision.
    Signature,
    /// The signature, the tree, and the ops all check out.
    Full,
}

/// Resolves a repository DID to the key its commits are signed with.
///
/// A trait rather than a concrete resolver because the caching is the
/// caller's: a firehose consumer resolves the same few thousand DIDs
/// repeatedly, and a resolver with no cache in front of it turns every commit
/// into a network round trip. `atproto-identity` has the pieces; what it does
/// not have is a policy about how long a signing key stays good, which depends
/// on whether the consumer also watches `#identity`.
#[async_trait]
pub trait SigningKeyResolver: Send + Sync {
    /// The `#atproto` signing key for `did`.
    ///
    /// Returning `Err` is reported as [`VerifyFailure::SigningKeyUnresolved`]
    /// and never as a bad signature: the usual cause is the DID's host being
    /// unreachable, which is somebody else's outage rather than this
    /// repository lying about itself.
    async fn signing_key(&self, did: &str) -> Result<KeyData, String>;
}

/// Read every block of a commit's CAR slice.
///
/// A commit slice is bounded by the write it describes, so reading it whole is
/// the right shape -- and the CAR limits in `atproto-dasl` are what keeps a
/// hostile relay from making that a memory problem.
async fn read_slice(
    repo: &str,
    blocks: &[u8],
) -> Result<Vec<atproto_dasl::car::CarBlock>, VerifyFailure> {
    let mut reader = CarReader::new(std::io::Cursor::new(blocks))
        .await
        .map_err(|error| VerifyFailure::Car {
            repo: repo.to_string(),
            error,
        })?;

    let mut car_blocks = Vec::new();
    while let Some(block) = reader
        .next_block()
        .await
        .map_err(|error| VerifyFailure::Car {
            repo: repo.to_string(),
            error,
        })?
    {
        car_blocks.push(block);
    }
    Ok(car_blocks)
}

/// A resolver behind an `Arc` is still a resolver: the cache it fronts is
/// almost always shared.
#[async_trait]
impl<T: SigningKeyResolver + ?Sized> SigningKeyResolver for std::sync::Arc<T> {
    async fn signing_key(&self, did: &str) -> Result<KeyData, String> {
        (**self).signing_key(did).await
    }
}

/// Verify a commit to the requested level.
///
/// `blocks` is the CAR slice from the event. `collections` filters which ops
/// are proven against the tree; an empty slice proves all of them.
///
/// # Errors
///
/// Returns the [`VerifyFailure`] naming what did not check out.
pub async fn verify_commit(
    level: VerificationLevel,
    envelope: &CommitEnvelope,
    blocks: &[u8],
    resolver: &dyn SigningKeyResolver,
    collections: &[&str],
) -> Result<Verification, VerifyFailure> {
    if level == VerificationLevel::Off {
        return Ok(Verification::Skipped);
    }

    let car_blocks = read_slice(&envelope.repo, blocks).await?;

    let commit_raw = envelope.commit.0;
    let commit_bytes = car_blocks
        .iter()
        .find(|block| block.cid == commit_raw)
        .map(|block| block.data.as_slice())
        .ok_or_else(|| VerifyFailure::CommitBlockMissing {
            repo: envelope.repo.clone(),
            commit: envelope.commit.to_string(),
        })?;

    let commit =
        Commit::from_bytes(commit_bytes).map_err(|error| VerifyFailure::CommitMalformed {
            repo: envelope.repo.clone(),
            reason: error.to_string(),
        })?;

    // The commit says which repository it belongs to, and the event says which
    // repository it came from. A relay that mixed them up would otherwise have
    // this check a real signature over a real commit belonging to somebody
    // else, and report success.
    if commit.did != envelope.repo {
        return Err(VerifyFailure::CommitMalformed {
            repo: envelope.repo.clone(),
            reason: format!(
                "commit is for {}, event is for {}",
                commit.did, envelope.repo
            ),
        });
    }

    let signing_bytes = commit
        .signing_bytes()
        .map_err(|error| VerifyFailure::CommitMalformed {
            repo: envelope.repo.clone(),
            reason: error.to_string(),
        })?;

    let key = resolver
        .signing_key(&envelope.repo)
        .await
        .map_err(|reason| VerifyFailure::SigningKeyUnresolved {
            repo: envelope.repo.clone(),
            reason,
        })?;

    validate(&key, &commit.sig, &signing_bytes).map_err(|_| VerifyFailure::Signature {
        repo: envelope.repo.clone(),
        rev: envelope.rev.clone(),
    })?;

    if level == VerificationLevel::SignatureOnly {
        return Ok(Verification::Signature);
    }

    verify_inductive(envelope.prev_data.clone(), commit.data.clone(), &car_blocks).map_err(
        |error| VerifyFailure::Tree {
            repo: envelope.repo.clone(),
            reason: error.to_string(),
        },
    )?;

    // And now the half `verify_inductive` cannot do, because it is never shown
    // the ops: prove that each one describes the tree it just checked.
    let inclusions =
        verify_op_inclusion(commit.data.clone(), &envelope.ops, &car_blocks, collections)
            .await
            .map_err(|error| VerifyFailure::Tree {
                repo: envelope.repo.clone(),
                reason: error.to_string(),
            })?;

    if let Some(bad) = inclusions.iter().find(|inclusion| !inclusion.verified) {
        return Err(VerifyFailure::OpInclusion {
            repo: envelope.repo.clone(),
            path: bad.path.clone(),
            detail: match &bad.found {
                Some(found) => format!("the tree resolves it to {found}"),
                None => "the tree does not hold it".to_string(),
            },
        });
    }

    Ok(Verification::Full)
}
