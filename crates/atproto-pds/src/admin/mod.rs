//! Admin subsystem — `com.atproto.admin.*` endpoints + operator dashboard.
//!
//! all endpoints are
//! Basic-auth gated by `PDS_ADMIN_PASSWORD`. The dashboard at `GET /admin`
//! mirrors the JSON API. `takedownSpaceRecord` (G15/§10.6) is part of the
//! Spaces moderation extension and lives in `crate::space`.

pub mod dashboard;
pub mod handlers;
pub mod subject;

pub use dashboard::dashboard as dashboard_handler;
pub use handlers::*;
pub use subject::{StatusAttr, SubjectRef};
