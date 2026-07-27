//! CAR v1 (Content Addressable aRchive) implementation.
//!
//! CAR files are used to transport IPLD data, particularly for AT Protocol
//! repository exports and sync operations.
//!
//! # Format Overview
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │ Header Section                          │
//! │ ┌─────────────────────────────────────┐ │
//! │ │ varint: header_length               │ │
//! │ │ dag-cbor: {version: 1, roots: [...]}│ │
//! │ └─────────────────────────────────────┘ │
//! ├─────────────────────────────────────────┤
//! │ Data Section (repeated)                 │
//! │ ┌─────────────────────────────────────┐ │
//! │ │ varint: cid_length + data_length    │ │
//! │ │ bytes: cid_bytes                    │ │
//! │ │ bytes: block_data                   │ │
//! │ └─────────────────────────────────────┘ │
//! │ .. more blocks ..                     │
//! └─────────────────────────────────────────┘
//! ```
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use atproto_dasl::car::{CarReader, CarWriter, CarBlock};
//! use tokio::fs::File;
//!
//! // Reading a CAR file
//! async fn read_car() -> anyhow::Result<()> {
//!     let file = File::open("repo.car").await?;
//!     let mut reader = CarReader::new(file).await?;
//!
//!     println!("Roots: {:?}", reader.roots());
//!
//!     while let Some(block) = reader.next_block().await? {
//!         println!("Block: {} ({} bytes)", block.cid, block.data.len());
//!     }
//!
//!     Ok(())
//! }
//!
//! // Writing a CAR file
//! async fn write_car() -> anyhow::Result<()> {
//!     let file = File::create("output.car").await?;
//!     let roots = vec![some_cid];
//!     let mut writer = CarWriter::new(file, roots).await?;
//!
//!     writer.write_block(&block).await?;
//!     writer.finish().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Specification
//!
//! See [CAR v1 Specification](https://ipld.io/specs/transport/car/carv1/)

mod block;
pub mod config;
mod header;
mod reader;
mod writer;

pub use block::{CarBlock, DASL_CID_BYTE_LENGTH, MAX_CID_BYTE_LENGTH};
pub use config::{CarConfig, LimitsConfig};
pub use header::CarHeader;
pub use reader::CarReader;
pub use writer::CarWriter;
