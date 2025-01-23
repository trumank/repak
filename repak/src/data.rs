use std::io::Write;

use crate::{
    entry::{Block, Entry},
    Compression, Error, Hash, Version, VersionMajor,
};

type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) fn get_limit(path: &str) -> usize {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x11, 0x22, 0x33, 0x44]);
    hasher.update(path.to_ascii_lowercase().as_bytes());
    let limit =
        ((u64::from_le_bytes(hasher.finalize().as_bytes()[0..8].try_into().unwrap()) % 0x3d) * 63
            + 319)
            & 0xffffffffffffffc0;
    if limit == 0 {
        0x1000
    } else {
        limit as usize
    }
}

pub(crate) fn pad_length(length: usize, alignment: usize) -> usize {
    length + (alignment - length % alignment) % alignment
}

pub(crate) fn pad_zeros_to_alignment(v: &mut Vec<u8>, alignment: usize) {
    v.resize(pad_length(v.len(), alignment), 0);
}

#[cfg(feature = "encryption")]
pub(crate) fn encrypt(key: &aes::Aes256, bytes: &mut [u8]) {
    use aes::cipher::BlockEncrypt;
    for chunk in bytes.chunks_mut(16) {
        chunk.chunks_mut(4).for_each(|c| c.reverse());
        key.encrypt_block(aes::Block::from_mut_slice(chunk));
        chunk.chunks_mut(4).for_each(|c| c.reverse());
    }
}

#[cfg(feature = "encryption")]
pub(crate) fn decrypt(key: &super::Key, bytes: &mut [u8]) -> Result<(), super::Error> {
    if let super::Key::Some(key) = key {
        use aes::cipher::BlockDecrypt;
        for chunk in bytes.chunks_mut(16) {
            chunk.chunks_mut(4).for_each(|c| c.reverse());
            key.decrypt_block(aes::Block::from_mut_slice(chunk));
            chunk.chunks_mut(4).for_each(|c| c.reverse());
        }
        Ok(())
    } else {
        Err(super::Error::Encrypted)
    }
}

pub struct PartialEntry<D: AsRef<[u8]>> {
    compression: Option<Compression>,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_block_size: u32,
    data: PartialEntryData<D>,
    encrypted: bool,
    hash: Hash,
}
pub(crate) struct PartialBlock {
    uncompressed_size: usize,
    compressed_size: usize,
}
pub(crate) enum PartialEntryData<D> {
    Slice(D),
    Blocks {
        data: Vec<u8>,
        blocks: Vec<PartialBlock>,
    },
}
impl<D: AsRef<[u8]>> AsRef<[u8]> for PartialEntryData<D> {
    fn as_ref(&self) -> &[u8] {
        match self {
            PartialEntryData::Slice(data) => data.as_ref(),
            PartialEntryData::Blocks { data, .. } => data,
        }
    }
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
            PartialEntryData::Blocks { blocks, .. } => {
                let entry_size =
                    Entry::get_serialized_size(version, compression_slot, blocks.len() as u32);

                let mut offset = entry_size;
                if version.version_major() < VersionMajor::RelativeChunkOffsets {
                    offset += file_offset;
                };

                if blocks.is_empty() {
                    None
                } else {
                    Some(
                        blocks
                            .iter()
                            .map(|block| {
                                let start = offset;
                                offset += block.compressed_size as u64;
                                let end = offset;
                                Block { start, end }
                            })
                            .collect(),
                    )
                }
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
            PartialEntryData::Blocks { data, .. } => {
                stream.write_all(data)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn build_partial_entry<D>(
    allowed_compression: &[Compression],
    data: D,
    #[allow(unused)] key: &super::Key,
    path: &str,
) -> Result<PartialEntry<D>>
where
    D: AsRef<[u8]>,
{
    // TODO hash needs to be post-compression/encryption
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();

    let mut encrypted = false;
    #[cfg(feature = "encryption")]
    if let super::Key::Some(_) = key {
        encrypted = true;
    }

    // TODO possibly select best compression based on some criteria instead of picking first
    let mut compression = allowed_compression.first().cloned();
    let uncompressed_size = data.as_ref().len() as u64;
    let compression_block_size;

    let mut data = match compression {
        #[cfg(not(feature = "compression"))]
        Some(_) => {
            unreachable!("should not be able to reach this point without compression feature")
        }
        #[cfg(feature = "compression")]
        Some(compression) if uncompressed_size > 0 => {
            // https://github.com/EpicGames/UnrealEngine/commit/3aad0ff7976be1073005dca2c1282af548b45d89
            // Block size must fit into flags field or it may cause unreadable paks for earlier Unreal Engine versions
            compression_block_size = 0x10000;
            let mut compressed_data = vec![];
            let mut blocks = vec![];
            for chunk in data.as_ref().chunks(compression_block_size as usize) {
                let mut data = compress(compression, chunk)?;
                if encrypted {
                    pad_zeros_to_alignment(&mut data, 16);
                }
                compressed_data.extend_from_slice(&data);
                hasher.update(&data);
                blocks.push(PartialBlock {
                    uncompressed_size: chunk.len(),
                    compressed_size: data.len(),
                })
            }

            PartialEntryData::Blocks {
                data: compressed_data,
                blocks,
            }
        }
        _ => {
            compression = None;
            compression_block_size = 0;
            hasher.update(data.as_ref());
            PartialEntryData::Slice(data)
        }
    };

    #[cfg(feature = "encryption")]
    if let super::Key::Some(key) = key {
        // convert to owned because we need to pad
        match data {
            PartialEntryData::Slice(inner) => {
                data = PartialEntryData::Blocks {
                    data: inner.as_ref().to_vec(),
                    blocks: vec![],
                };
            }
            PartialEntryData::Blocks { .. } => {}
        }

        match &mut data {
            PartialEntryData::Slice(_) => unreachable!(),
            PartialEntryData::Blocks { data, .. } => {
                let limit = crate::data::get_limit(path);
                let limit = if limit > data.len() {
                    pad_zeros_to_alignment(data, 16);
                    data.len()
                } else {
                    limit
                };
                encrypt(key, &mut data[..limit]);
            }
        }
    }

    Ok(PartialEntry {
        compression,
        compressed_size: data.as_ref().len() as u64,
        uncompressed_size,
        compression_block_size,
        data,
        hash: Hash(hasher.finalize().into()),
        encrypted,
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
