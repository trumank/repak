use crate::{
    entry::{Block, Entry},
    Compression, Error, Hash, Version, VersionMajor,
};

type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) struct PartialEntry {
    compression: Option<Compression>,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_block_size: u32,
    pub(crate) blocks: Vec<PartialBlock>,
    hash: Hash,
}
pub(crate) struct PartialBlock {
    uncompressed_size: usize,
    pub(crate) data: Vec<u8>,
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

impl PartialEntry {
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

        let blocks = (!self.blocks.is_empty()).then(|| {
            let entry_size =
                Entry::get_serialized_size(version, compression_slot, self.blocks.len() as u32);

            let mut offset = entry_size;
            if version.version_major() < VersionMajor::RelativeChunkOffsets {
                offset += file_offset;
            };

            self.blocks
                .iter()
                .map(|block| {
                    let start = offset;
                    offset += block.data.len() as u64;
                    let end = offset;
                    Block { start, end }
                })
                .collect()
        });

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
}

pub(crate) fn build_partial_entry(
    allowed_compression: &[Compression],
    data: &[u8],
) -> Result<PartialEntry> {
    // TODO hash needs to be post-compression/encryption
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();

    // TODO possibly select best compression based on some criteria instead of picking first
    let compression = allowed_compression.first().cloned();
    let uncompressed_size = data.len() as u64;
    let compression_block_size;

    let (blocks, compressed_size) = match compression {
        #[cfg(not(feature = "compression"))]
        Some(_) => {
            unreachable!("should not be able to reach this point without compression feature")
        }
        #[cfg(feature = "compression")]
        Some(compression) => {
            compression_block_size = 0x10000;
            let mut compressed_size = 0;
            let mut blocks = vec![];
            for chunk in data.chunks(compression_block_size as usize) {
                let data = compress(compression, chunk)?;
                compressed_size += data.len() as u64;
                hasher.update(&data);
                blocks.push(PartialBlock {
                    uncompressed_size: chunk.len(),
                    data,
                })
            }

            (blocks, compressed_size)
        }
        None => {
            compression_block_size = 0;
            hasher.update(data);
            (vec![], uncompressed_size)
        }
    };

    Ok(PartialEntry {
        compression,
        compressed_size,
        uncompressed_size,
        compression_block_size,
        blocks,
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
                let mut output = vec![];
                oodle_loader::oodle()
                    .unwrap()
                    .compress(
                        data.as_ref(),
                        &mut output,
                        oodle_loader::Compressor::Mermaid,
                        oodle_loader::CompressionLevel::Normal,
                    )
                    .unwrap();
                output
            }
        }
    };

    Ok(compressed)
}
