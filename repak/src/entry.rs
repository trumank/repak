use crate::Error;

use super::{ext::BoolExt, ext::ReadExt, Compression, Version, VersionMajor};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::io;

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum EntryLocation {
    Data,
    Index,
}

#[derive(Debug)]
pub(crate) struct Block {
    pub start: u64,
    pub end: u64,
}

impl Block {
    pub fn read<R: io::Read>(reader: &mut R) -> Result<Self, super::Error> {
        Ok(Self {
            start: reader.read_u64::<LE>()?,
            end: reader.read_u64::<LE>()?,
        })
    }

    pub fn write<W: io::Write>(&self, writer: &mut W) -> Result<(), super::Error> {
        writer.write_u64::<LE>(self.start)?;
        writer.write_u64::<LE>(self.end)?;
        Ok(())
    }
}

fn align(offset: u64) -> u64 {
    // add alignment (aes block size: 16) then zero out alignment bits
    (offset + 15) & !15
}

#[derive(Debug)]
pub(crate) struct Entry {
    pub offset: u64,
    pub compressed: u64,
    pub uncompressed: u64,
    pub compression_slot: Option<u32>,
    pub timestamp: Option<u64>,
    pub hash: Option<[u8; 20]>,
    pub blocks: Option<Vec<Block>>,
    pub flags: u8,
    pub compression_block_size: u32,
}

impl Entry {
    pub fn is_encrypted(&self) -> bool {
        0 != (self.flags & 1)
    }
    pub fn is_deleted(&self) -> bool {
        0 != (self.flags >> 1) & 1
    }
    pub fn get_serialized_size(
        version: super::Version,
        compression: Option<u32>,
        block_count: u32,
    ) -> u64 {
        let mut size = 0;
        size += 8; // offset
        size += 8; // compressed
        size += 8; // uncompressed
        size += match version != Version::V8A {
            true => 4,  // 32 bit compression
            false => 1, // 8 bit compression
        };
        size += match version.version_major() == VersionMajor::Initial {
            true => 8, // timestamp
            false => 0,
        };
        size += 20; // hash
        size += match compression {
            Some(_) => 4 + (8 + 8) * block_count as u64, // blocks
            None => 0,
        };
        size += 1; // encrypted
        size += match version.version_major() >= VersionMajor::CompressionEncryption {
            true => 4, // blocks uncompressed
            false => 0,
        };
        size
    }

    pub(crate) fn write_file<W: io::Write + io::Seek>(
        writer: &mut W,
        version: Version,
        compression_slots: &mut Vec<Option<Compression>>,
        allowed_compression: &[Compression],
        data: impl AsRef<[u8]>,
    ) -> Result<Self, super::Error> {
        // TODO hash needs to be post-compression
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(&data);

        let offset = writer.stream_position()?;
        let len = data.as_ref().len() as u64;

        // TODO possibly select best compression based on some criteria instead of picking first
        let compression = allowed_compression.first().cloned();

        let compression_slot = if let Some(compression) = compression {
            // find existing
            let slot = compression_slots
                .iter()
                .enumerate()
                .find(|(_, s)| **s == Some(compression));
            Some(if let Some((i, _)) = slot {
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
        } else {
            None
        };

        let (blocks, compressed) = match compression {
            #[cfg(not(feature = "compression"))]
            Some(_) => {
                unreachable!("should not be able to reach this point without compression feature")
            }
            #[cfg(feature = "compression")]
            Some(compression) => {
                use std::io::Write;

                let entry_size = Entry::get_serialized_size(version, compression_slot, 1);
                let data_offset = offset + entry_size;

                let compressed = match compression {
                    Compression::Zlib => {
                        let mut compress = flate2::write::ZlibEncoder::new(
                            Vec::new(),
                            flate2::Compression::fast(),
                        );
                        compress.write_all(data.as_ref())?;
                        compress.finish()?
                    }
                    Compression::Gzip => {
                        let mut compress =
                            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                        compress.write_all(data.as_ref())?;
                        compress.finish()?
                    }
                    Compression::Zstd => zstd::stream::encode_all(data.as_ref(), 0)?,
                    Compression::Oodle => {
                        return Err(Error::Other("writing Oodle compression unsupported".into()))
                    }
                };

                let compute_offset = |index: usize| -> u64 {
                    match version.version_major() >= VersionMajor::RelativeChunkOffsets {
                        true => index as u64 + (data_offset - offset),
                        false => index as u64 + data_offset,
                    }
                };

                let blocks = vec![Block {
                    start: compute_offset(0),
                    end: compute_offset(compressed.len()),
                }];

                (Some(blocks), Some(compressed))
            }
            None => (None, None),
        };

        let entry = super::entry::Entry {
            offset,
            compressed: compressed
                .as_ref()
                .map(|c: &Vec<u8>| c.len() as u64)
                .unwrap_or(len),
            uncompressed: len,
            compression_slot,
            timestamp: None,
            hash: Some(hasher.finalize().into()),
            blocks,
            flags: 0,
            compression_block_size: compressed.as_ref().map(|_| len as u32).unwrap_or_default(),
        };

        entry.write(writer, version, EntryLocation::Data)?;

        if let Some(compressed) = compressed {
            writer.write_all(&compressed)?;
        } else {
            writer.write_all(data.as_ref())?;
        }

        Ok(entry)
    }

    pub fn read<R: io::Read>(
        reader: &mut R,
        version: super::Version,
    ) -> Result<Self, super::Error> {
        let ver = version.version_major();
        let offset = reader.read_u64::<LE>()?;
        let compressed = reader.read_u64::<LE>()?;
        let uncompressed = reader.read_u64::<LE>()?;
        let compression = match if version == Version::V8A {
            reader.read_u8()? as u32
        } else {
            reader.read_u32::<LE>()?
        } {
            0 => None,
            n => Some(n - 1),
        };
        let timestamp = (ver == VersionMajor::Initial).then_try(|| reader.read_u64::<LE>())?;
        let hash = Some(reader.read_guid()?);
        let blocks = (ver >= VersionMajor::CompressionEncryption && compression.is_some())
            .then_try(|| reader.read_array(Block::read))?;
        let compression_block_size = (ver >= VersionMajor::CompressionEncryption)
            .then_try(|| reader.read_u32::<LE>())?
            .unwrap_or(0);
        let flags = (ver >= VersionMajor::CompressionEncryption)
            .then_try(|| reader.read_u8())?
            .unwrap_or(0);
        Ok(Self {
            offset,
            compressed,
            uncompressed,
            compression_slot: compression,
            timestamp,
            hash,
            blocks,
            flags,
            compression_block_size,
        })
    }

    pub fn write<W: io::Write>(
        &self,
        writer: &mut W,
        version: super::Version,
        location: EntryLocation,
    ) -> Result<(), super::Error> {
        writer.write_u64::<LE>(match location {
            EntryLocation::Data => 0,
            EntryLocation::Index => self.offset,
        })?;
        writer.write_u64::<LE>(self.compressed)?;
        writer.write_u64::<LE>(self.uncompressed)?;
        let compression = self.compression_slot.map_or(0, |n| n + 1);
        match version {
            Version::V8A => writer.write_u8(compression.try_into().unwrap())?,
            _ => writer.write_u32::<LE>(compression)?,
        }

        if version.version_major() == VersionMajor::Initial {
            writer.write_u64::<LE>(self.timestamp.unwrap_or_default())?;
        }
        if let Some(hash) = self.hash {
            writer.write_all(&hash)?;
        } else {
            panic!("hash missing");
        }
        if version.version_major() >= VersionMajor::CompressionEncryption {
            if let Some(blocks) = &self.blocks {
                writer.write_u32::<LE>(blocks.len() as u32)?;
                for block in blocks {
                    block.write(writer)?;
                }
            }
            writer.write_u32::<LE>(self.compression_block_size)?;
            writer.write_u8(self.flags)?;
        }

        Ok(())
    }

    pub fn read_encoded<R: io::Read>(
        reader: &mut R,
        version: super::Version,
    ) -> Result<Self, super::Error> {
        let bits = reader.read_u32::<LE>()?;
        let compression = match (bits >> 23) & 0x3f {
            0 => None,
            n => Some(n - 1),
        };

        let encrypted = (bits & (1 << 22)) != 0;
        let compression_block_count: u32 = (bits >> 6) & 0xffff;
        let mut compression_block_size = bits & 0x3f;

        if compression_block_size == 0x3f {
            compression_block_size = reader.read_u32::<LE>()?;
        } else {
            compression_block_size <<= 11;
        }

        let mut var_int = |bit: u32| -> Result<_, super::Error> {
            Ok(if (bits & (1 << bit)) != 0 {
                reader.read_u32::<LE>()? as u64
            } else {
                reader.read_u64::<LE>()?
            })
        };

        let offset = var_int(31)?;
        let uncompressed = var_int(30)?;
        let compressed = match compression {
            None => uncompressed,
            _ => var_int(29)?,
        };

        let offset_base = Entry::get_serialized_size(version, compression, compression_block_count);

        let blocks = if compression_block_count == 1 && !encrypted {
            Some(vec![Block {
                start: offset_base,
                end: offset_base + compressed,
            }])
        } else if compression_block_count > 0 {
            let mut index = offset_base;
            Some(
                (0..compression_block_count)
                    .map(|_| {
                        let mut block_size = reader.read_u32::<LE>()? as u64;
                        let block = Block {
                            start: index,
                            end: index + block_size,
                        };
                        if encrypted {
                            block_size = align(block_size);
                        }
                        index += block_size;
                        Ok(block)
                    })
                    .collect::<Result<Vec<_>, super::Error>>()?,
            )
        } else {
            None
        };

        Ok(Entry {
            offset,
            compressed,
            uncompressed,
            timestamp: None,
            compression_slot: compression,
            hash: None,
            blocks,
            flags: encrypted as u8,
            compression_block_size,
        })
    }

    pub fn write_encoded<W: io::Write>(&self, writer: &mut W) -> Result<(), super::Error> {
        let mut compression_block_size = (self.compression_block_size >> 11) & 0x3f;
        if (compression_block_size << 11) != self.compression_block_size {
            compression_block_size = 0x3f;
        }
        let compression_blocks_count = if self.compression_slot.is_some() {
            self.blocks.as_ref().unwrap().len() as u32
        } else {
            0
        };
        let is_size_32_bit_safe = self.compressed <= u32::MAX as u64;
        let is_uncompressed_size_32_bit_safe = self.uncompressed <= u32::MAX as u64;
        let is_offset_32_bit_safe = self.offset <= u32::MAX as u64;

        let flags = (compression_block_size)
            | (compression_blocks_count << 6)
            | ((self.is_encrypted() as u32) << 22)
            | (self.compression_slot.map_or(0, |n| n + 1) << 23)
            | ((is_size_32_bit_safe as u32) << 29)
            | ((is_uncompressed_size_32_bit_safe as u32) << 30)
            | ((is_offset_32_bit_safe as u32) << 31);

        writer.write_u32::<LE>(flags)?;

        if compression_block_size == 0x3f {
            writer.write_u32::<LE>(self.compression_block_size)?;
        }

        if is_offset_32_bit_safe {
            writer.write_u32::<LE>(self.offset as u32)?;
        } else {
            writer.write_u64::<LE>(self.offset)?;
        }

        if is_uncompressed_size_32_bit_safe {
            writer.write_u32::<LE>(self.uncompressed as u32)?
        } else {
            writer.write_u64::<LE>(self.uncompressed)?
        }

        if self.compression_slot.is_some() {
            if is_size_32_bit_safe {
                writer.write_u32::<LE>(self.compressed as u32)?;
            } else {
                writer.write_u64::<LE>(self.compressed)?;
            }

            assert!(self.blocks.is_some());
            let blocks = self.blocks.as_ref().unwrap();
            if blocks.len() > 1 || self.is_encrypted() {
                for b in blocks {
                    let block_size = b.end - b.start;
                    writer.write_u32::<LE>(block_size.try_into().unwrap())?;
                }
            }
        }

        Ok(())
    }

    pub fn read_file<R: io::Read + io::Seek, W: io::Write>(
        &self,
        reader: &mut R,
        version: Version,
        compression: &[Option<Compression>],
        #[allow(unused)] key: &super::Key,
        #[allow(unused)] oodle: &super::Oodle,
        buf: &mut W,
    ) -> Result<(), super::Error> {
        reader.seek(io::SeekFrom::Start(self.offset))?;
        Entry::read(reader, version)?;
        #[cfg(any(feature = "compression", feature = "oodle"))]
        let data_offset = reader.stream_position()?;
        #[allow(unused_mut)]
        let mut data = reader.read_len(match self.is_encrypted() {
            true => align(self.compressed),
            false => self.compressed,
        } as usize)?;
        if self.is_encrypted() {
            #[cfg(not(feature = "encryption"))]
            return Err(super::Error::Encryption);
            #[cfg(feature = "encryption")]
            {
                let super::Key::Some(key) = key else {
                    return Err(super::Error::Encrypted);
                };
                use aes::cipher::BlockDecrypt;
                for block in data.chunks_mut(16) {
                    key.decrypt_block(aes::Block::from_mut_slice(block))
                }
                data.truncate(self.compressed as usize);
            }
        }

        #[cfg(any(feature = "compression", feature = "oodle"))]
        let ranges = {
            let offset = |index: u64| -> usize {
                (match version.version_major() >= VersionMajor::RelativeChunkOffsets {
                    true => index - (data_offset - self.offset),
                    false => index - data_offset,
                }) as usize
            };

            match &self.blocks {
                Some(blocks) => blocks
                    .iter()
                    .map(|block| offset(block.start)..offset(block.end))
                    .collect::<Vec<_>>(),
                #[allow(clippy::single_range_in_vec_init)]
                None => vec![0..data.len()],
            }
        };

        #[cfg(feature = "compression")]
        macro_rules! decompress {
            ($decompressor: ty) => {
                for range in ranges {
                    io::copy(&mut <$decompressor>::new(&data[range]), buf)?;
                }
            };
        }

        match self.compression_slot.and_then(|c| compression[c as usize]) {
            None => buf.write_all(&data)?,
            #[cfg(feature = "compression")]
            Some(Compression::Zlib) => decompress!(flate2::read::ZlibDecoder<&[u8]>),
            #[cfg(feature = "compression")]
            Some(Compression::Gzip) => decompress!(flate2::read::GzDecoder<&[u8]>),
            #[cfg(feature = "compression")]
            Some(Compression::Zstd) => {
                for range in ranges {
                    io::copy(&mut zstd::stream::read::Decoder::new(&data[range])?, buf)?;
                }
            }
            #[cfg(feature = "oodle")]
            Some(Compression::Oodle) => {
                let oodle = match oodle {
                    crate::Oodle::Some(getter) => getter().map_err(|_| super::Error::OodleFailed),
                    crate::Oodle::None => Err(super::Error::OodleFailed),
                }?;
                let mut decompressed = vec![0; self.uncompressed as usize];

                let mut compress_offset = 0;
                let mut decompress_offset = 0;
                let block_count = ranges.len();
                for range in ranges {
                    let decomp = if block_count == 1 {
                        self.uncompressed as usize
                    } else {
                        (self.compression_block_size as usize)
                            .min(self.uncompressed as usize - compress_offset)
                    };
                    let buffer = &mut data[range];
                    let out = oodle(
                        buffer,
                        &mut decompressed[decompress_offset..decompress_offset + decomp],
                    );
                    if out == 0 {
                        return Err(super::Error::DecompressionFailed(Compression::Oodle));
                    }
                    compress_offset += self.compression_block_size as usize;
                    decompress_offset += out as usize;
                }

                debug_assert_eq!(
                    decompress_offset, self.uncompressed as usize,
                    "Oodle decompression length mismatch"
                );
                buf.write_all(&decompressed)?;
            }
            #[cfg(not(feature = "oodle"))]
            Some(Compression::Oodle) => return Err(super::Error::Oodle),
            #[cfg(not(feature = "compression"))]
            _ => return Err(super::Error::Compression),
        }
        buf.flush()?;
        Ok(())
    }
}

mod test {
    #[test]
    fn test_entry() {
        let data = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xDD, 0x94, 0xFD, 0xC3, 0x5F, 0xF5, 0x91, 0xA9, 0x9A, 0x5E, 0x14, 0xDC, 0x9B,
            0xD3, 0x58, 0x89, 0x78, 0xA6, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut out = vec![];
        let entry = super::Entry::read(&mut std::io::Cursor::new(data.clone()), super::Version::V5)
            .unwrap();
        entry
            .write(&mut out, super::Version::V5, super::EntryLocation::Data)
            .unwrap();
        assert_eq!(&data, &out);
    }
}
