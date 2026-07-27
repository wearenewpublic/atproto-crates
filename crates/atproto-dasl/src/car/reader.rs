//! Async streaming CAR v1 reader.
//!
//! The reader lazily reads blocks on demand for memory efficiency and
//! integrates with the `BlockStorage` trait for flexible backends.

use super::CarConfig;
use super::block::async_io as block_io;
use super::header::async_io as header_io;
use super::{CarBlock, CarHeader};
use crate::Cid;
use crate::errors::CarError;
use crate::storage::BlockStorage;
use tokio::io::AsyncRead;

/// Async streaming CAR v1 reader.
///
/// Reads blocks lazily from an async source, verifying CIDs if configured.
///
/// # Example
///
/// ```rust,ignore
/// use atproto_dasl::CarReader;
/// use tokio::fs::File;
///
/// async fn example() -> anyhow::Result<()> {
///     let file = File::open("repo.car").await?;
///     let mut reader = CarReader::new(file).await?;
///
///     println!("Roots: {:?}", reader.roots());
///
///     while let Some(block) = reader.next_block().await? {
///         println!("Block: {} ({} bytes)", block.cid, block.data.len());
///     }
///
///     Ok(())
/// }
/// ```
pub struct CarReader<R> {
    reader: R,
    header: CarHeader,
    config: CarConfig,
    blocks_read: usize,
    bytes_read: u64,
}

impl<R: AsyncRead + Unpin> CarReader<R> {
    /// Create a new reader with default configuration.
    ///
    /// # Errors
    ///
    /// Returns `CarError` if the header cannot be read or is invalid.
    pub async fn new(reader: R) -> Result<Self, CarError> {
        Self::with_config(reader, CarConfig::default()).await
    }

    /// Create a new reader with custom configuration.
    ///
    /// # Errors
    ///
    /// Returns `CarError` if the header cannot be read or is invalid.
    pub async fn with_config(mut reader: R, config: CarConfig) -> Result<Self, CarError> {
        let header = header_io::read_header(&mut reader).await?;

        Ok(Self {
            reader,
            header,
            config,
            blocks_read: 0,
            bytes_read: 0,
        })
    }

    /// Get the CAR header.
    #[must_use]
    pub fn header(&self) -> &CarHeader {
        &self.header
    }

    /// Get root CIDs.
    #[must_use]
    pub fn roots(&self) -> &[Cid] {
        &self.header.roots
    }

    /// Get the first root CID.
    #[must_use]
    pub fn root(&self) -> Option<&Cid> {
        self.header.roots.first()
    }

    /// Get number of blocks read so far.
    #[must_use]
    pub fn blocks_read(&self) -> usize {
        self.blocks_read
    }

    /// Get number of bytes read so far (excluding header).
    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> &CarConfig {
        &self.config
    }

    /// Read the next block.
    ///
    /// Returns `None` at EOF.
    ///
    /// # Verification
    ///
    /// - If `config.verify_cids` is true, verifies that the CID matches the data.
    /// - If `config.strict_cid_format` is true, verifies the CID format.
    ///
    /// # Limits
    ///
    /// - Enforces `config.limits.max_block_size` per block. The declared wire
    ///   length is checked **before** the block buffer is allocated, and the
    ///   decoded data is checked again once the CID has been parsed.
    /// - Enforces `config.limits.max_block_count` total blocks.
    /// - Enforces `config.limits.max_car_size` total bytes.
    ///
    /// # Errors
    ///
    /// Returns `CarError` if reading fails or verification fails.
    pub async fn next_block(&mut self) -> Result<Option<CarBlock>, CarError> {
        // Check block count limit
        if self.blocks_read >= self.config.limits.max_block_count {
            return Err(CarError::InvalidBlock {
                reason: format!(
                    "block count limit exceeded: {} >= {}",
                    self.blocks_read, self.config.limits.max_block_count
                ),
            });
        }

        // Read block. The limits are enforced inside, before the block buffer
        // is allocated, so a hostile length prefix cannot amplify a few bytes
        // of input into a huge allocation.
        let block =
            match block_io::read_block_with_limits(&mut self.reader, &self.config.limits).await? {
                Some(b) => b,
                None => return Ok(None),
            };

        // Re-check the block size as defense in depth.
        if block.data.len() > self.config.limits.max_block_size {
            return Err(CarError::BlockTooLarge {
                size: block.data.len() as u64,
                max: self.config.limits.max_block_size as u64,
            });
        }

        // Update stats
        let block_bytes = block.cid.to_bytes().len() + block.data.len();
        self.bytes_read += block_bytes as u64;
        self.blocks_read += 1;

        // Check total size limit
        if self.bytes_read > self.config.limits.max_car_size {
            return Err(CarError::FileTooLarge {
                size: self.bytes_read,
                max: self.config.limits.max_car_size,
            });
        }

        // Verify CID if configured
        if self.config.verify_cids {
            block.verify()?;
        }

        // Verify format if configured
        if self.config.strict_cid_format {
            block.verify_format()?;
        }

        Ok(Some(block))
    }

    /// Stream all blocks into a storage backend.
    ///
    /// Efficient for large CAR files - blocks are streamed directly
    /// to storage without buffering the entire file.
    ///
    /// # Errors
    ///
    /// Returns `CarError` if reading or storage fails.
    pub async fn stream_to_storage<S: BlockStorage>(
        mut self,
        storage: &mut S,
    ) -> Result<CarHeader, CarError> {
        while let Some(block) = self.next_block().await? {
            storage.put(&block.cid, block.data).await?;
        }
        Ok(self.header)
    }

    /// Consume the reader and return the underlying reader.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.reader
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::car::{CarBlock, CarHeader, CarWriter};
    use crate::storage::MemoryStorage;
    use std::io::Cursor;

    async fn create_test_car() -> Vec<u8> {
        let data1 = b"block one".to_vec();
        let block1 = CarBlock::from_data(data1);

        let data2 = b"block two".to_vec();
        let block2 = CarBlock::from_data(data2);

        let header = CarHeader::new(vec![block1.cid.into()]).unwrap();

        let mut buffer = Vec::new();
        let mut writer = CarWriter::new(&mut buffer, header.roots.clone())
            .await
            .unwrap();
        writer.write_block(&block1).await.unwrap();
        writer.write_block(&block2).await.unwrap();
        writer.finish().await.unwrap();

        buffer
    }

    #[tokio::test]
    async fn test_read_car() {
        let car_bytes = create_test_car().await;
        let mut reader = CarReader::new(Cursor::new(&car_bytes)).await.unwrap();

        assert_eq!(reader.roots().len(), 1);

        let block1 = reader.next_block().await.unwrap().unwrap();
        assert_eq!(block1.data, b"block one");

        let block2 = reader.next_block().await.unwrap().unwrap();
        assert_eq!(block2.data, b"block two");

        assert!(reader.next_block().await.unwrap().is_none());
        assert_eq!(reader.blocks_read(), 2);
    }

    #[tokio::test]
    async fn test_stream_to_storage() {
        let car_bytes = create_test_car().await;
        let reader = CarReader::new(Cursor::new(&car_bytes)).await.unwrap();

        let mut storage = MemoryStorage::new();
        let header = reader.stream_to_storage(&mut storage).await.unwrap();

        assert_eq!(header.roots.len(), 1);
        assert_eq!(storage.block_count(), 2);
    }

    #[tokio::test]
    async fn test_verify_cids() {
        let car_bytes = create_test_car().await;
        let config = CarConfig::default();

        let mut reader = CarReader::with_config(Cursor::new(&car_bytes), config)
            .await
            .unwrap();

        // All blocks should verify
        while let Some(_block) = reader.next_block().await.unwrap() {}
    }

    #[tokio::test]
    async fn test_block_size_limit() {
        // Create a CAR with a large block
        let data = vec![0u8; 1000];
        let block = CarBlock::from_data(data);
        let header = CarHeader::new(vec![block.cid.into()]).unwrap();

        let mut buffer = Vec::new();
        let mut writer = CarWriter::new(&mut buffer, header.roots.clone())
            .await
            .unwrap();
        writer.write_block(&block).await.unwrap();
        writer.finish().await.unwrap();

        // Try to read with small block limit
        let config = CarConfig::default()
            .with_limits(crate::LimitsConfig::default().with_max_block_size(100));

        let mut reader = CarReader::with_config(Cursor::new(&buffer), config)
            .await
            .unwrap();

        let result = reader.next_block().await;
        assert!(matches!(result, Err(CarError::BlockTooLarge { .. })));
    }
}
