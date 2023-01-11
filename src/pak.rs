use std::io;

use super::ReadExt;
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
    ) -> Result<Self, super::Error> {
        reader.seek(io::SeekFrom::End(-version.size()))?;
        let footer = super::Footer::new(&mut reader, version)?;
        reader.seek(io::SeekFrom::Start(footer.offset))?;
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
