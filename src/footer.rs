use super::{ext::ReadExt, Compression, Version, VersionMajor};
use byteorder::{ReadBytesExt, LE};
use std::str::FromStr;

#[derive(Debug)]
pub struct Footer {
    pub encryption_uuid: Option<u128>,
    pub encrypted: bool,
    pub magic: u32,
    pub version: Version,
    pub version_major: VersionMajor,
    pub index_offset: u64,
    pub index_size: u64,
    pub hash: [u8; 20],
    pub frozen: bool,
    pub compression: Vec<Compression>,
}

impl Footer {
    pub fn new<R: std::io::Read>(reader: &mut R, version: Version) -> Result<Self, super::Error> {
        let footer = Self {
            encryption_uuid: match version.version_major() >= VersionMajor::EncryptionKeyGuid {
                true => Some(reader.read_u128::<LE>()?),
                false => None,
            },
            encrypted: version.version_major() >= VersionMajor::IndexEncryption && reader.read_bool()?,
            magic: reader.read_u32::<LE>()?,
            version,
            version_major: VersionMajor::from_repr(reader.read_u32::<LE>()?).unwrap_or(version.version_major()),
            index_offset: reader.read_u64::<LE>()?,
            index_size: reader.read_u64::<LE>()?,
            hash: reader.read_guid()?,
            frozen: version.version_major() == VersionMajor::FrozenIndex && reader.read_bool()?,
            compression: {
                let mut compression = Vec::with_capacity(match version {
                    ver if ver < Version::V8A => 0,
                    ver if ver < Version::V8B => 4,
                    _ => 5,
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
            },
        };
        if super::MAGIC != footer.magic {
            return Err(super::Error::Magic(footer.magic));
        }
        if version.version_major() != footer.version_major {
            return Err(super::Error::Version {
                used: version,
                version: footer.version,
            });
        }
        Ok(footer)
    }
}
