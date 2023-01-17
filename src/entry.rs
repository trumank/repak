use super::{ext::ReadExt, Compression, Version};
use byteorder::{ReadBytesExt, LE};
use std::io;

#[derive(Debug)]
pub struct Block {
    pub start: u64,
    pub end: u64,
}

impl Block {
    pub fn new<R: io::Read>(reader: &mut R) -> Result<Self, super::Error> {
        Ok(Self {
            start: reader.read_u64::<LE>()?,
            end: reader.read_u64::<LE>()?,
        })
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
    pub block_uncompressed: Option<u32>,
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
        size += 4; // compression
        size += match version == Version::Initial {
            true => 8, // timestamp
            false => 0,
        };
        size += 20; // hash
        size += match compression != Compression::None {
            true => 4 + (8 + 8) * block_count as u64, // blocks
            false => 0,
        };
        size += 1; // encrypted
        size += match version >= Version::CompressionEncryption {
            true => 4, // blocks uncompressed
            false => 0,
        };
        size
    }

    pub fn new<R: io::Read>(reader: &mut R, version: super::Version) -> Result<Self, super::Error> {
        // since i need the compression flags, i have to store these as variables which is mildly annoying
        let offset = reader.read_u64::<LE>()?;
        let compressed = reader.read_u64::<LE>()?;
        let uncompressed = reader.read_u64::<LE>()?;
        let compression = match reader.read_u32::<LE>()? {
            0x01 | 0x10 | 0x20 => Compression::Zlib,
            _ => Compression::None,
        };
        Ok(Self {
            offset,
            compressed,
            uncompressed,
            compression,
            timestamp: match version == Version::Initial {
                true => Some(reader.read_u64::<LE>()?),
                false => None,
            },
            hash: Some(reader.read_guid()?),
            blocks: match version >= Version::CompressionEncryption
                && compression != Compression::None
            {
                true => Some(reader.read_array(Block::new)?),
                false => None,
            },
            encrypted: version >= Version::CompressionEncryption && reader.read_bool()?,
            block_uncompressed: match version >= Version::CompressionEncryption {
                true => Some(reader.read_u32::<LE>()?),
                false => None,
            },
        })
    }

    pub fn new_encoded<R: io::Read>(
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
        let mut block_uncompressed = bits & 0x3f;

        if block_uncompressed == 0x3f {
            block_uncompressed = reader.read_u32::<LE>()?;
        } else {
            block_uncompressed = block_uncompressed << 11;
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

        block_uncompressed = if compression_block_count <= 0 {
            0
        } else if uncompressed < block_uncompressed.into() {
            uncompressed.try_into().unwrap()
        } else {
            block_uncompressed
        };

        let offset_base =
            match version >= super::Version::RelativeChunkOffsets {
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
                    .into_iter()
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
            block_uncompressed: Some(block_uncompressed),
        })
    }

    pub fn read<R: io::Read + io::Seek, W: io::Write>(
        &self,
        reader: &mut R,
        version: super::Version,
        key: Option<&aes::Aes256Dec>,
        buf: &mut W,
    ) -> Result<(), super::Error> {
        reader.seek(io::SeekFrom::Start(self.offset))?;
        Entry::new(reader, version)?;
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
                                    &data[match version >= Version::RelativeChunkOffsets {
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
