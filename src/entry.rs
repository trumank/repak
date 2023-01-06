use byteorder::{ReadBytesExt, LE};

use super::{Compression, ReadExt, Version};

#[derive(Debug)]
pub struct Entry {
    pub name: String,
    pub offset: u64,
    pub compressed: u64,
    pub uncompressed: u64,
    pub compression_method: Compression,
    pub timestamp: Option<u64>,
    pub hash: [u8; 20],
    pub compression_blocks: Option<Vec<Block>>,
}

impl Entry {
    pub fn new<R: std::io::Read>(
        reader: &mut R,
        version: &super::Version,
    ) -> Result<Self, super::Error> {
        let name = reader.read_string()?;
        let offset = reader.read_u64::<LE>()?;
        let compressed = reader.read_u64::<LE>()?;
        let uncompressed = reader.read_u64::<LE>()?;
        let compression_method = match reader.read_u32::<LE>()? {
            0x01 => Compression::Zlib,
            0x10 => Compression::ZlibBiasMemory,
            0x20 => Compression::ZlibBiasMemory,
            _ => Compression::None,
        };
        Ok(Self {
            name,
            offset,
            compressed,
            uncompressed,
            compression_method,
            timestamp: (version == &Version::Initial).then_some(reader.read_u64::<LE>()?),
            hash: reader.read_guid()?,
            compression_blocks: (version >= &Version::CompressionEncryption
                && compression_method != Compression::None)
                .then_some(reader.read_array(Block::new)?),
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
