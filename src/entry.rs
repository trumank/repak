use byteorder::{ReadBytesExt, LE};

use super::{Compression, ReadExt, Version};

#[derive(Debug)]
pub struct Entry {
    pub offset: u64,
    pub compressed: u64,
    pub uncompressed: u64,
    pub compression_method: Compression,
    pub timestamp: Option<u64>,
    pub hash: [u8; 20],
    pub compression_blocks: Option<Vec<Block>>,
    pub encrypted: bool,
    pub block_uncompressed: Option<u32>,
}

impl Entry {
    pub fn new<R: std::io::Read>(
        reader: &mut R,
        version: super::Version,
    ) -> Result<Self, super::Error> {
        let offset = reader.read_u64::<LE>()?;
        let compressed = reader.read_u64::<LE>()?;
        let uncompressed = reader.read_u64::<LE>()?;
        let compression_method = match reader.read_u32::<LE>()? {
            0x01 | 0x10 | 0x20 => Compression::Zlib,
            _ => Compression::None,
        };
        Ok(Self {
            offset,
            compressed,
            uncompressed,
            compression_method,
            timestamp: match version == Version::Initial {
                true => Some(reader.read_u64::<LE>()?),
                false => None,
            },
            hash: reader.read_guid()?,
            compression_blocks: match version >= Version::CompressionEncryption
                && compression_method != Compression::None
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
}

#[derive(Debug)]
pub struct Block {
    /// start offset relative to the start of the entry header
    pub offset: u64,
    /// size of the compressed block
    pub size: u64,
}

impl Block {
    pub fn new<R: std::io::Read>(reader: &mut R) -> Result<Self, super::Error> {
        Ok(Self {
            offset: reader.read_u64::<LE>()?,
            size: reader.read_u64::<LE>()?,
        })
    }
}
