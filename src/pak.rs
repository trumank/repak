use std::io;

use super::ReadExt;
use aes::cipher::{BlockDecrypt, KeyInit};
use byteorder::{ReadBytesExt, LE};

use super::Version;

#[derive(Debug)]
pub struct Pak {
    pub version: Version,
    pub footer: super::Footer,
    pub mount_point: String,
    pub entries: hashbrown::HashMap<String, super::Entry>,
}

impl Pak {
    pub fn new<R: io::Read + io::Seek>(
        mut reader: R,
        version: super::Version,
        key: Option<&[u8]>,
    ) -> Result<Self, super::Error> {
        reader.seek(io::SeekFrom::End(-version.size()))?;
        let footer = super::Footer::new(&mut reader, version)?;
        reader.seek(io::SeekFrom::Start(footer.offset))?;
        let mut index = reader.read_len(footer.size as usize)?;
        if let Some(key) = key {
            match aes::Aes256Dec::new_from_slice(key) {
                Ok(key) => {
                    for chunk in index.chunks_mut(16) {
                        key.decrypt_block(aes::Block::from_mut_slice(chunk))
                    }
                }
                Err(_) => return Err(super::Error::Aes),
            }
        }
        let mount_point = reader.read_string()?;
        let len = reader.read_u32::<LE>()? as usize;
        let mut entries = hashbrown::HashMap::with_capacity(len);
        for _ in 0..len {
            entries.insert(
                reader.read_string()?,
                super::Entry::new(&mut reader, version)?,
            );
        }
        Ok(Self {
            version,
            footer,
            mount_point,
            entries,
        })
    }
}
