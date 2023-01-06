use std::io;

use super::Version;

pub struct Pak {
    pub version: Version,
    pub footer: super::Footer,
    pub index: super::Index,
}

impl Pak {
    pub fn new<R: io::Read + io::Seek>(
        version: super::Version,
        mut reader: R,
    ) -> Result<Self, super::Error> {
        reader.seek(io::SeekFrom::End(-footer_size(&version)))?;
        let footer = super::Footer::new(&mut reader, &version)?;
        reader.seek(io::SeekFrom::Start(footer.offset))?;
        let index = super::Index::new(&mut reader, &version)?;
        Ok(Self {
            version,
            footer,
            index,
        })
    }
}

fn footer_size(version: &Version) -> i64 {
    // (magic + version): u32 + (offset + size): u64 + hash: [u8; 20]
    let mut size = 4 + 4 + 8 + 8 + 20;
    if version >= &Version::EncryptionKeyGuid {
        // encryption guid: [u8; 20]
        size += 20;
    }
    if version >= &Version::IndexEncryption {
        // encrypted: bool
        size += 1;
    }
    if version == &Version::FrozenIndex {
        // frozen index: bool
        size += 1;
    }
    if version >= &Version::FNameBasedCompression {
        // compression names: [[u8; 32]; 4]
        size += 32 * 4;
    }
    if version >= &Version::FrozenIndex {
        // extra compression name: [u8; 32]
        size += 32
    }
    size
}
