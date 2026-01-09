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
}
pub(crate) struct PartialBlock {
    uncompressed_size: usize,
    data: Vec<u8>,
}
pub(crate) enum PartialEntryData<D> {
    Slice(D),
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
        encrypted: bool,
    ) -> Result<Entry> {
        #[cfg(feature = "compression")]
        let compression_slot = {
            let empty = match &self.data {
                PartialEntryData::Slice(s) => s.as_ref().is_empty(),
                PartialEntryData::Blocks(blocks) => blocks.is_empty(),
            };
            if empty {
                None
            } else {
                self.compression
                    .map(|c| get_compression_slot(version, compression_slots, c))
                    .transpose()?
            }
        };
        #[cfg(not(feature = "compression"))]
        let compression_slot = None;

        // When encrypted, compressed_size must account for per-block padding
        let compressed_size_actual = if encrypted {
            match &self.data {
                PartialEntryData::Slice(_) => {
                    // Single block: align total size
                    (self.compressed_size + 15) & !15
                }
                PartialEntryData::Blocks(blocks) => {
                    // Multiple blocks: sum of aligned block sizes
                    blocks
                        .iter()
                        .map(|b| (b.data.len() as u64 + 15) & !15)
                        .sum()
                }
            }
        } else {
            self.compressed_size
        };

        // Blocks are needed even when encrypting - they guide decompression
        // Each block is an independent compressed stream in the encrypted data
        let blocks = match &self.data {
            PartialEntryData::Slice(_) => None,
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
                            let start = offset;
                            offset += block.data.len() as u64;
                            let end = offset;
                            Block { start, end }
                        })
                        .collect(),
                )
            }
        };

        Ok(Entry {
            offset: file_offset,
            compressed: compressed_size_actual,
            uncompressed: self.uncompressed_size,
            compression_slot,
            timestamp: None,
            hash: Some(self.hash),
            blocks,
            flags: if encrypted { 1 } else { 0 }, // Bit 0 = encrypted flag
            compression_block_size: self.compression_block_size,
        })
    }

    /// Get all data as a Vec for encryption
    pub(crate) fn get_data_vec(&self) -> Vec<u8> {
        match &self.data {
            PartialEntryData::Slice(data) => data.as_ref().to_vec(),
            PartialEntryData::Blocks(blocks) => {
                let mut result = Vec::new();
                for block in blocks {
                    result.extend_from_slice(&block.data);
                }
                result
            }
        }
    }
    pub(crate) fn write_data<S: Write>(&self, stream: &mut S) -> Result<()> {
        match &self.data {
            PartialEntryData::Slice(data) => {
                stream.write_all(data.as_ref())?;
            }
            PartialEntryData::Blocks(blocks) => {
                for block in blocks {
                    stream.write_all(&block.data)?;
                }
            }
        }
        Ok(())
    }

    /// Write encrypted data with per-block padding for encrypted multi-block files
    pub(crate) fn write_encrypted_data<S: Write, F>(
        &self,
        stream: &mut S,
        mut encrypt_fn: F,
    ) -> Result<()>
    where
        F: FnMut(&mut Vec<u8>) -> Result<()>,
    {
        match &self.data {
            PartialEntryData::Slice(data) => {
                let mut data = data.as_ref().to_vec();
                let pad_len = (16 - (data.len() % 16)) % 16;
                data.resize(data.len() + pad_len, 0);
                encrypt_fn(&mut data)?;
                stream.write_all(&data)?;
            }
            PartialEntryData::Blocks(blocks) => {
                // Encrypt each block individually with padding
                for block in blocks {
                    let mut data = block.data.clone();
                    let pad_len = (16 - (data.len() % 16)) % 16;
                    data.resize(data.len() + pad_len, 0);
                    encrypt_fn(&mut data)?;
                    stream.write_all(&data)?;
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn build_partial_entry<D>(
    allowed_compression: &[Compression],
    data: D,
) -> Result<PartialEntry<D>>
where
    D: AsRef<[u8]>,
{
    // TODO hash needs to be post-compression/encryption
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();

    // TODO possibly select best compression based on some criteria instead of picking first
    let compression = allowed_compression.first().cloned();
    let uncompressed_size = data.as_ref().len() as u64;
    let compression_block_size;

    let (data, compressed_size) = match compression {
        #[cfg(not(feature = "compression"))]
        Some(_) => {
            unreachable!("should not be able to reach this point without compression feature")
        }
        #[cfg(feature = "compression")]
        Some(compression) => {
            // Use 64KB blocks to match original game paks
            // For files smaller than 64KB, use the file size as block size
            let max_block_size = 65536; // 64KB = 0x10000 = 0x20 << 11
            compression_block_size = std::cmp::min(uncompressed_size as u32, max_block_size);

            let mut compressed_size = 0;
            let mut blocks = vec![];
            for chunk in data.as_ref().chunks(compression_block_size as usize) {
                let data = compress(compression, chunk)?;
                compressed_size += data.len() as u64;
                hasher.update(&data);
                blocks.push(PartialBlock {
                    uncompressed_size: chunk.len(),
                    data,
                })
            }

            (PartialEntryData::Blocks(blocks), compressed_size)
        }
        None => {
            compression_block_size = 0;
            hasher.update(data.as_ref());
            (PartialEntryData::Slice(data), uncompressed_size)
        }
    };

    Ok(PartialEntry {
        compression,
        compressed_size,
        uncompressed_size,
        compression_block_size,
        data,
        hash: Hash(hasher.finalize().into()),
    })
}

#[cfg(feature = "compression")]
fn compress(compression: Compression, data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;

    let compressed = match compression {
        Compression::Zlib => {
            let mut compress =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            compress.write_all(data.as_ref())?;
            compress.finish()?
        }
        Compression::Gzip => {
            let mut compress =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
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
