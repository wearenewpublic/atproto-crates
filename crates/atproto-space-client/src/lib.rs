//! The XRPC client half of proposal 0016 permissioned data.
//!
//! `atproto-space` implements the 0016 primitives -- `LtHash`, signed commits,
//! `DelegationToken`, `SpaceCredential` -- and is deliberately network-free,
//! so it composes with a server through storage traits and does no IO of its
//! own. That is the right shape for a PDS. For a consumer it means every type
//! needed to *read* a space is there and nothing knows how to obtain one.
//!
//! This crate is that, and it is a separate crate rather than a feature of
//! `atproto-space` because "has no network dependencies" is a property that
//! crate states in its own documentation. A feature flag would make it
//! conditional; a sibling keeps it unconditional, and a consumer that wants
//! both writes one more line.
//!
//! # The credential chain is three parties agreeing to three things
//!
//! Reading a space someone else hosts takes three calls to two servers:
//!
//! 1. **`getDelegationToken`**, at the **member's own PDS**. OAuth-gated, and
//!    it refuses an app-password session outright: the token asserts *an
//!    application is acting for this user*, which a password session cannot
//!    express.
//! 2. **`getSpaceCredential`**, at the **authority**. The delegation token
//!    travels as a `Bearer` with a DPoP proof beside it, and the credential
//!    comes back bound to that proof's key.
//! 3. **`registerNotify`**, at the **authority**. The credential travels under
//!    the `DPoP` scheme with a proof of possession.
//!
//! Two servers, and which call goes to which is not obvious -- see
//! [`SpaceHosts`], which exists because getting it wrong is invisible until it
//! is not.
//!
//! # Bound and Grant are not interchangeable
//!
//! Hops 1 and 3 present a token *bound* to the session key; hop 2 presents a
//! *grant*. The two differ in the scheme (`DPoP` versus `Bearer`) and in the
//! proof (`ath` present versus absent), and getting it backwards produces
//! `401 missing DPoP header` from a server that was never asked about
//! membership. [`atproto_client::client::DpopPresentation`] is where that
//! distinction lives.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod credential;
pub mod errors;
pub mod methods;
pub mod spaces;
mod transport;

pub use credential::{
    Delivery, SpaceCredentialGrant, SpaceHosts, Subscription, space_read_credential,
    subscribe_to_space, unsubscribe_from_space,
};
pub use errors::SpaceClientError;
pub use spaces::{
    CreateSpace, ListSpaces, Member, MemberPage, SpaceConfig, SpacePage, SpaceSession,
    SpaceSummary, create_space, delete_space, get_space, list_members, list_spaces,
};
