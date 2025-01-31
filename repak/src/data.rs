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
    ) -> Result<Entry> {
        #[cfg(feature = "compression")]
        let compression_slot = self
            .compression
            .map(|c| get_compression_slot(version, compression_slots, c))
            .transpose()?;
        #[cfg(not(feature = "compression"))]
        let compression_slot = None;

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
            compressed: self.compressed_size,
            uncompressed: self.uncompressed_size,
            compression_slot,
            timestamp: None,
            hash: Some(self.hash),
            blocks,
            flags: 0,
            compression_block_size: self.compression_block_size,
        })
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
            // https://github.com/EpicGames/UnrealEngine/commit/3aad0ff7976be1073005dca2c1282af548b45d89
            // Block size must fit into flags field or it may cause unreadable paks for earlier Unreal Engine versions
            compression_block_size = 0x3e << 11; // max possible block size
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
