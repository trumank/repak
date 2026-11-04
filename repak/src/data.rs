use std::io::Write;

use crate::{
    entry::{Block, Entry},
    Compression, Error, Hash, Version, VersionMajor,
};

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct PartialEntry<D: AsRef<[u8]>> {
    compression: Option<Compression>,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_block_size: u32,
    data: PartialEntryData<D>,
    hash: Hash,
    encrypted: bool,
}
pub(crate) struct PartialBlock {
    uncompressed_size: usize,
    /// Compressed size before padding for encryption
    unpadded_size: usize,
    data: Vec<u8>,
}
pub(crate) enum PartialEntryData<D> {
    Slice(D),
    /// Uncompressed data, padded and encrypted
    Encrypted(Vec<u8>),
    Blocks(Vec<PartialBlock>),
}

#[cfg(feature = "compression")]
fn get_compression_slot(
    version: Version,
    compression_slots: &mut Vec<Option<Compression>>,
    compression: Compression,
) -> Result<u32> {
    let slot = compression_slots
        .iter()
        .enumerate()
        .find(|(_, s)| **s == Some(compression));
    Ok(if let Some((i, _)) = slot {
        // existing found
        i
    } else {
        if version.version_major() < VersionMajor::FNameBasedCompression {
            return Err(Error::Other(format!(
                "cannot use {compression:?} prior to FNameBasedCompression (pak version 8)"
            )));
        }

        // find empty slot
        if let Some((i, empty_slot)) = compression_slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.is_none())
        {
            // empty found, set it to used compression type
            *empty_slot = Some(compression);
            i
        } else {
            // no empty slot found, add a new one
            compression_slots.push(Some(compression));
            compression_slots.len() - 1
        }
    } as u32)
}

impl<D: AsRef<[u8]>> PartialEntry<D> {
    pub(crate) fn build_entry(
        &self,
        version: Version,
        #[allow(unused)] compression_slots: &mut Vec<Option<Compression>>,
        file_offset: u64,
    ) -> Result<Entry> {
        #[cfg(feature = "compression")]
        let compression_slot = self
            .compression
            .map(|c| get_compression_slot(version, compression_slots, c))
            .transpose()?;
        #[cfg(not(feature = "compression"))]
        let compression_slot = None;

        assert!(
            compression_slot.is_none()
                || !matches!(&self.data, PartialEntryData::Blocks(b) if b.is_empty()),
            "compressed entry must have at least one block"
        );

        if self.encrypted && version.version_major() < VersionMajor::CompressionEncryption {
            return Err(Error::Other(
                "cannot encrypt entries prior to CompressionEncryption (pak version 3)".to_owned(),
            ));
        }

        let blocks = match &self.data {
            PartialEntryData::Slice(_) | PartialEntryData::Encrypted(_) => None,
            PartialEntryData::Blocks(blocks) => {
                let entry_size =
                    Entry::get_serialized_size(version, compression_slot, blocks.len() as u32);

                let mut offset = entry_size;
                if version.version_major() < VersionMajor::RelativeChunkOffsets {
                    offset += file_offset;
                };

                Some(
                    blocks
                        .iter()
                        .map(|block| {
                            // an encrypted block ends before its padding
                            let start = offset;
                            offset += block.data.len() as u64;
                            let end = start + block.unpadded_size as u64;
                            Block { start, end }
                        })
                        .collect(),
                )
            }
        };

        Ok(Entry {
            offset: file_offset,
            compressed: self.compressed_size,
            uncompressed: self.uncompressed_size,
            compression_slot,
            timestamp: None,
            hash: Some(self.hash),
            blocks,
            flags: self.encrypted as u8,
            compression_block_size: self.compression_block_size,
        })
    }
    pub(crate) fn write_data<S: Write>(&self, stream: &mut S) -> Result<()> {
        match &self.data {
            PartialEntryData::Slice(data) => {
                stream.write_all(data.as_ref())?;
            }
            PartialEntryData::Encrypted(data) => {
                stream.write_all(data)?;
            }
            PartialEntryData::Blocks(blocks) => {
                for block in blocks {
                    stream.write_all(&block.data)?;
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn build_partial_entry<D>(
    allowed_compression: &[Compression],
    data: D,
    key: &super::Key,
) -> Result<PartialEntry<D>>
where
    D: AsRef<[u8]>,
{
    // UnrealPak hashes the stored bytes (compressed and encrypted), excluding the padding of
    // uncompressed data
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();

    // Empty data cannot be compressed (would produce empty blocks causing decompression failures)
    let compression = if data.as_ref().is_empty() {
        None
    } else {
        // TODO possibly select best compression based on some criteria instead of picking first
        allowed_compression.first().cloned()
    };
    let uncompressed_size = data.as_ref().len() as u64;
    let compression_block_size;

    let (data, compressed_size) = match compression {
        #[cfg(not(feature = "compression"))]
        Some(_) => {
            unreachable!("should not be able to reach this point without compression feature")
        }
        #[cfg(feature = "compression")]
        Some(compression) => {
            // https://github.com/EpicGames/UnrealEngine/commit/3aad0ff7976be1073005dca2c1282af548b45d89
            // Block size must fit into flags field or it may cause unreadable paks for earlier Unreal Engine versions
            compression_block_size = 0x3e << 11; // max possible block size
            let mut compressed_size = 0;
            let mut blocks = vec![];
            for chunk in data.as_ref().chunks(compression_block_size as usize) {
                #[allow(unused_mut)]
                let mut data = compress(compression, chunk)?;
                let block_compressed_size = data.len();
                #[cfg(feature = "encryption")]
                if let super::Key::Some(key) = key {
                    // each block is padded and encrypted separately
                    crate::pak::pad_to_aes_block(&mut data);
                    crate::pak::encrypt(key, &mut data);
                }
                compressed_size += data.len() as u64;
                hasher.update(&data);
                blocks.push(PartialBlock {
                    uncompressed_size: chunk.len(),
                    unpadded_size: block_compressed_size,
                    data,
                })
            }

            (PartialEntryData::Blocks(blocks), compressed_size)
        }
        None => {
            compression_block_size = 0;
            match key {
                #[cfg(feature = "encryption")]
                super::Key::Some(key) => {
                    let mut data = data.as_ref().to_vec();
                    crate::pak::pad_to_aes_block(&mut data);
                    crate::pak::encrypt(key, &mut data);
                    hasher.update(&data[..uncompressed_size as usize]);
                    (PartialEntryData::Encrypted(data), uncompressed_size)
                }
                _ => {
                    hasher.update(data.as_ref());
                    (PartialEntryData::Slice(data), uncompressed_size)
                }
            }
        }
    };

    Ok(PartialEntry {
        compression,
        compressed_size,
        uncompressed_size,
        compression_block_size,
        data,
        hash: Hash(hasher.finalize().into()),
        encrypted: !matches!(key, super::Key::None),
    })
}

#[cfg(feature = "compression")]
fn compress(compression: Compression, data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;

    let compressed = match compression {
        Compression::Zlib => {
            let mut compress =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            compress.write_all(data.as_ref())?;
            compress.finish()?
        }
        Compression::Gzip => {
            let mut compress =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            compress.write_all(data.as_ref())?;
            compress.finish()?
        }
        Compression::Zstd => zstd::stream::encode_all(data, 0)?,
        Compression::LZ4 => lz4_flex::block::compress(data),
        Compression::Oodle => {
            #[cfg(not(feature = "oodle"))]
            return Err(super::Error::Oodle);
            #[cfg(feature = "oodle")]
            {
                oodle_loader::oodle().unwrap().compress(
                    data.as_ref(),
                    oodle_loader::Compressor::Mermaid,
                    oodle_loader::CompressionLevel::Normal,
                )?
            }
        }
    };

    Ok(compressed)
}

#[cfg(all(test, feature = "compression", feature = "encryption"))]
mod test {
    use super::*;

    /// Layout of UnrealPak's encrypted compressed entries: each block is padded to 16 bytes, the
    /// block records end before the padding, and the hash covers the encrypted, padded blocks.
    #[test]
    fn test_encrypted_blocks() {
        use aes::cipher::KeyInit;
        use sha1::{Digest, Sha1};
        let key = aes::Aes256::new_from_slice(&[7; 32]).unwrap();
        let data = (0..300_000u64)
            .map(|i| ((i * i) >> 7) as u8)
            .collect::<Vec<_>>();

        let partial = build_partial_entry(&[Compression::Zlib], &data, &key.into()).unwrap();
        let entry = partial.build_entry(Version::V11, &mut vec![], 0).unwrap();
        let mut written = vec![];
        partial.write_data(&mut written).unwrap();

        assert!(entry.is_encrypted());
        let blocks = entry.blocks.unwrap();
        assert!(blocks.len() > 1);
        assert_eq!(entry.compressed, written.len() as u64);
        assert_eq!(
            entry.hash.unwrap().0,
            <[u8; 20]>::from(Sha1::digest(&written))
        );
        let mut start = blocks[0].start;
        for block in &blocks {
            assert_eq!(block.start, start);
            assert_ne!(block.end % 16, start % 16, "test data should need padding");
            start += (block.end - block.start).next_multiple_of(16);
        }
        assert_eq!(start - blocks[0].start, written.len() as u64);
    }
}
