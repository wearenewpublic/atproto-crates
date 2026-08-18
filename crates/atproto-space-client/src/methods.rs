//! The XRPC method names this client speaks.
//!
//! Named constants rather than inline strings, because a method name wrong by
//! a word is a `404` from a server that is working correctly, and because
//! [`REQUIRED_SPACE_METHODS`] is the list a capability probe compares against.

/// `com.atproto.space.getDelegationToken` -- hop 1, at the member's PDS.
pub const GET_DELEGATION_TOKEN: &str = "com.atproto.space.getDelegationToken";
/// `com.atproto.space.getSpaceCredential` -- hop 2, at the authority.
pub const GET_SPACE_CREDENTIAL: &str = "com.atproto.space.getSpaceCredential";
/// `com.atproto.space.registerNotify` -- hop 3, at the authority.
pub const REGISTER_NOTIFY: &str = "com.atproto.space.registerNotify";
/// `com.atproto.space.unregisterNotify`.
pub const UNREGISTER_NOTIFY: &str = "com.atproto.space.unregisterNotify";
/// `com.atproto.space.notifyWrite`.
pub const NOTIFY_WRITE: &str = "com.atproto.space.notifyWrite";
/// `com.atproto.space.notifySpaceDeleted`.
pub const NOTIFY_SPACE_DELETED: &str = "com.atproto.space.notifySpaceDeleted";
/// `com.atproto.space.listSpaces`.
pub const LIST_SPACES: &str = "com.atproto.space.listSpaces";
/// `com.atproto.space.applyWrites`.
pub const APPLY_WRITES: &str = "com.atproto.space.applyWrites";
/// `com.atproto.space.createRecord`.
pub const CREATE_RECORD: &str = "com.atproto.space.createRecord";
/// `com.atproto.space.putRecord`.
pub const PUT_RECORD: &str = "com.atproto.space.putRecord";
/// `com.atproto.space.deleteRecord`.
pub const DELETE_RECORD: &str = "com.atproto.space.deleteRecord";
/// `com.atproto.space.getRecord`.
pub const GET_RECORD: &str = "com.atproto.space.getRecord";
/// `com.atproto.space.listRecords`.
pub const LIST_RECORDS: &str = "com.atproto.space.listRecords";
/// `com.atproto.space.listRepos`.
pub const LIST_REPOS: &str = "com.atproto.space.listRepos";
/// `com.atproto.space.getRepo`.
pub const GET_REPO: &str = "com.atproto.space.getRepo";
/// `com.atproto.space.getLatestCommit`.
pub const GET_LATEST_COMMIT: &str = "com.atproto.space.getLatestCommit";
/// `com.atproto.space.getRepoState`.
pub const GET_REPO_STATE: &str = "com.atproto.space.getRepoState";

/// Every method a host must advertise to be usable as a space host.
///
/// Deliberately **excludes** the `com.atproto.simplespace.*` surface. Those
/// are one implementation's space-management endpoints, not the 0016 data
/// plane, and a host that does not offer them is not thereby unable to serve
/// spaces -- it just does not let this client create them.
pub const REQUIRED_SPACE_METHODS: [&str; 17] = [
    GET_DELEGATION_TOKEN,
    GET_SPACE_CREDENTIAL,
    REGISTER_NOTIFY,
    UNREGISTER_NOTIFY,
    NOTIFY_WRITE,
    NOTIFY_SPACE_DELETED,
    LIST_SPACES,
    APPLY_WRITES,
    CREATE_RECORD,
    PUT_RECORD,
    DELETE_RECORD,
    GET_RECORD,
    LIST_RECORDS,
    LIST_REPOS,
    GET_REPO,
    GET_LATEST_COMMIT,
    GET_REPO_STATE,
];

/// `com.atproto.simplespace.createSpace`.
pub const CREATE_SPACE: &str = "com.atproto.simplespace.createSpace";
/// `com.atproto.simplespace.deleteSpace`.
pub const DELETE_SPACE: &str = "com.atproto.simplespace.deleteSpace";
/// `com.atproto.simplespace.listMembers`.
pub const LIST_MEMBERS: &str = "com.atproto.simplespace.listMembers";
/// `com.atproto.simplespace.getSpace`.
pub const GET_SPACE: &str = "com.atproto.simplespace.getSpace";
