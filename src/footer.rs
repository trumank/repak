use std::str::FromStr;

use byteorder::{ReadBytesExt, LE};

use super::{Compression, ReadExt, Version};

pub struct Footer {
    pub encryption_guid: Option<[u8; 20]>,
    pub encrypted: Option<bool>,
    pub magic: u32,
    pub version: Version,
    pub offset: u64,
    pub size: u64,
    pub hash: [u8; 20],
    pub frozen: Option<bool>,
    pub compression: Option<Vec<Compression>>,
}

impl Footer {
    pub fn new<R: std::io::Read>(reader: &mut R, version: &Version) -> Result<Self, super::Error> {
        let footer = Footer {
            encryption_guid: (version >= &Version::EncryptionKeyGuid)
                .then_some(reader.read_guid()?),
            encrypted: (version >= &Version::CompressionEncryption).then_some(reader.read_bool()?),
            magic: reader.read_u32::<LE>()?,
            version: Version::from_repr(reader.read_u32::<LE>()?).unwrap_or_default(),
            offset: reader.read_u64::<LE>()?,
            size: reader.read_u64::<LE>()?,
            hash: reader.read_guid()?,
            frozen: (version == &Version::FrozenIndex).then_some(reader.read_bool()?),
            compression: (version >= &Version::FNameBasedCompression).then_some({
                let mut compression =
                    Vec::with_capacity(if version == &Version::FNameBasedCompression {
                        4
                    } else {
                        5
                    });
                for _ in 0..compression.capacity() {
                    compression.push(
                        Compression::from_str(
                            &reader
                                .read_len(32)?
                                .iter()
                                // filter out whitespace and convert to char
                                .filter_map(|&ch| (ch != 0).then_some(ch as char))
                                .collect::<String>(),
                        )
                        .unwrap_or_default(),
                    )
                }
                compression
            }),
        };
        if super::MAGIC != footer.magic {
            return Err(super::Error::PakInvalid(format!(
                "incorrect magic - expected {} but got {}",
                super::MAGIC,
                footer.magic
            )));
        }
        if version != &footer.version {
            return Err(super::Error::PakInvalid(format!(
                "incorrect version - parsed with {} but is {}",
                version, footer.version
            )));
        }
        Ok(footer)
    }
}
