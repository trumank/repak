use std::io;

use super::ReadExt;
use byteorder::{ReadBytesExt, LE};

use super::Version;

#[derive(Debug)]
pub struct Pak {
    pub version: Version,
    pub footer: super::Footer,
    pub mount_point: String,
}

impl Pak {
    pub fn new<R: io::Read + io::Seek>(
        version: super::Version,
        mut reader: R,
    ) -> Result<Self, super::Error> {
        reader.seek(io::SeekFrom::End(-version.size()))?;
        let footer = super::Footer::new(&mut reader, version)?;
        reader.seek(io::SeekFrom::Start(footer.offset))?;
        let mount_point = reader.read_string()?;
        let mut entries = hashbrown::HashMap::with_capacity(reader.read_u32::<LE>()? as usize);
        for _ in 0..entries.capacity() {
            entries.insert(
                dbg!(reader.read_string()?),
                dbg!(super::Entry::new(&mut reader, version)?),
            );
        }
        Ok(Self {
            version,
            footer,
            mount_point,
        })
    }
}
