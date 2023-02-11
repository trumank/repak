use super::{ext::ReadExt, ext::WriteExt, Compression, Version, VersionMajor};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::io;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum EntryLocation {
    Data,
    Index,
}

#[derive(Debug)]
pub struct Block {
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
pub struct Entry {
    pub offset: u64,
    pub compressed: u64,
    pub uncompressed: u64,
    pub compression: Compression,
    pub timestamp: Option<u64>,
    pub hash: Option<[u8; 20]>,
    pub blocks: Option<Vec<Block>>,
    pub encrypted: bool,
    pub compression_block_size: u32,
}

impl Entry {
    pub fn get_serialized_size(
        version: super::Version,
        compression: Compression,
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
        size += match compression != Compression::None {
            true => 4 + (8 + 8) * block_count as u64, // blocks
            false => 0,
        };
        size += 1; // encrypted
        size += match version.version_major() >= VersionMajor::CompressionEncryption {
            true => 4, // blocks uncompressed
            false => 0,
        };
        size
    }

    pub fn read<R: io::Read>(
        reader: &mut R,
        version: super::Version,
    ) -> Result<Self, super::Error> {
        // since i need the compression flags, i have to store these as variables which is mildly annoying
        let offset = reader.read_u64::<LE>()?;
        let compressed = reader.read_u64::<LE>()?;
        let uncompressed = reader.read_u64::<LE>()?;
        let compression = match if version == Version::V8A {
            reader.read_u8()? as u32
        } else {
            reader.read_u32::<LE>()?
        } {
            0x01 | 0x10 | 0x20 => Compression::Zlib,
            _ => Compression::None,
        };
        Ok(Self {
            offset,
            compressed,
            uncompressed,
            compression,
            timestamp: match version.version_major() == VersionMajor::Initial {
                true => Some(reader.read_u64::<LE>()?),
                false => None,
            },
            hash: Some(reader.read_guid()?),
            blocks: match version.version_major() >= VersionMajor::CompressionEncryption
                && compression != Compression::None
            {
                true => Some(reader.read_array(Block::read)?),
                false => None,
            },
            encrypted: version.version_major() >= VersionMajor::CompressionEncryption
                && reader.read_bool()?,
            compression_block_size: match version.version_major()
                >= VersionMajor::CompressionEncryption
            {
                true => reader.read_u32::<LE>()?,
                false => 0,
            },
        })
    }

    pub fn write<W: io::Write>(
        &self,
        writer: &mut W,
        version: super::Version,
        location: EntryLocation,
    ) -> Result<(), super::Error> {
        if version >= super::Version::V10 && location == EntryLocation::Index {
            let mut compression_block_size = (self.compression_block_size >> 11) & 0x3f;
            if (compression_block_size << 11) != self.compression_block_size {
                compression_block_size = 0x3f;
            }
            let compression_blocks_count = if self.compression != Compression::None {
                self.blocks.as_ref().unwrap().len() as u32
            } else {
                0
            };
            let is_size_32_bit_safe = self.compressed <= u32::MAX as u64;
            let is_uncompressed_size_32_bit_safe = self.uncompressed <= u32::MAX as u64;
            let is_offset_32_bit_safe = self.offset <= u32::MAX as u64;

            let flags = (compression_block_size)
                | (compression_blocks_count << 6)
                | ((self.encrypted as u32) << 22)
                | ((self.compression as u32) << 23)
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

            if self.compression != Compression::None {
                if is_size_32_bit_safe {
                    writer.write_u32::<LE>(self.compressed as u32)?;
                } else {
                    writer.write_u64::<LE>(self.compressed)?;
                }

                assert!(self.blocks.is_some());
                let blocks = self.blocks.as_ref().unwrap();
                if !blocks.len() == 1 || self.encrypted {
                    for b in blocks {
                        let block_size = b.end - b.start;
                        writer.write_u32::<LE>(block_size.try_into().unwrap())?;
                    }
                }
            }

            Ok(())
        } else {
            writer.write_u64::<LE>(match location {
                EntryLocation::Data => 0,
                EntryLocation::Index => self.offset,
            })?;
            writer.write_u64::<LE>(self.compressed)?;
            writer.write_u64::<LE>(self.uncompressed)?;
            let compression: u8 = match self.compression {
                Compression::None => 0,
                Compression::Zlib => 1,
                Compression::Gzip => todo!(),
                Compression::Oodle => todo!(),
            };
            match version {
                Version::V8A => writer.write_u8(compression)?,
                _ => writer.write_u32::<LE>(compression.into())?,
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
                writer.write_bool(self.encrypted)?;
                writer.write_u32::<LE>(self.compression_block_size)?;
            }

            Ok(())
        }
    }

    pub fn read_encoded<R: io::Read>(
        reader: &mut R,
        version: super::Version,
    ) -> Result<Self, super::Error> {
        let bits = reader.read_u32::<LE>()?;
        let compression = match (bits >> 23) & 0x3f {
            0x01 | 0x10 | 0x20 => Compression::Zlib,
            _ => Compression::None,
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
            Compression::None => uncompressed,
            _ => var_int(29)?,
        };

        let offset_base =
            match version.version_major() >= VersionMajor::RelativeChunkOffsets {
                true => 0,
                false => offset,
            } + Entry::get_serialized_size(version, compression, compression_block_count);

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
            compression,
            hash: None,
            blocks,
            encrypted,
            compression_block_size,
        })
    }

    pub fn read_file<R: io::Read + io::Seek, W: io::Write>(
        &self,
        reader: &mut R,
        version: Version,
        key: Option<&aes::Aes256>,
        buf: &mut W,
    ) -> Result<(), super::Error> {
        reader.seek(io::SeekFrom::Start(self.offset))?;
        Entry::read(reader, version)?;
        let data_offset = reader.stream_position()?;
        let mut data = reader.read_len(match self.encrypted {
            true => align(self.compressed),
            false => self.compressed,
        } as usize)?;
        if self.encrypted {
            let Some(key) = key else {
                return Err(super::Error::Encrypted);
            };
            use aes::cipher::BlockDecrypt;
            for block in data.chunks_mut(16) {
                key.decrypt_block(aes::Block::from_mut_slice(block))
            }
            data.truncate(self.compressed as usize);
        }
        macro_rules! decompress {
            ($decompressor: ty) => {
                match &self.blocks {
                    Some(blocks) => {
                        for block in blocks {
                            io::copy(
                                &mut <$decompressor>::new(
                                    &data[match version.version_major()
                                        >= VersionMajor::RelativeChunkOffsets
                                    {
                                        true => {
                                            (block.start - (data_offset - self.offset)) as usize
                                                ..(block.end - (data_offset - self.offset)) as usize
                                        }
                                        false => {
                                            (block.start - data_offset) as usize
                                                ..(block.end - data_offset) as usize
                                        }
                                    }],
                                ),
                                buf,
                            )?;
                        }
                    }
                    None => {
                        io::copy(&mut flate2::read::ZlibDecoder::new(data.as_slice()), buf)?;
                    }
                }
            };
        }
        match self.compression {
            Compression::None => buf.write_all(&data)?,
            Compression::Zlib => decompress!(flate2::read::ZlibDecoder<&[u8]>),
            Compression::Gzip => decompress!(flate2::read::GzDecoder<&[u8]>),
            Compression::Oodle => todo!(),
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
