use super::{ReadExt, Version};

#[derive(Debug)]
pub enum Index {
    WithoutPathHash(IndexV1),
    WithPathHash,
}

impl Index {
    pub fn new<R: std::io::Read>(reader: &mut R, version: Version) -> Result<Self, super::Error> {
        Ok(match version < Version::PathHashIndex {
            true => Index::WithoutPathHash(IndexV1::new(reader, version)?),
            false => Index::WithPathHash,
        })
    }
}

#[derive(Debug)]
pub struct IndexV1 {
    pub mount_point: String,
    pub entries: Vec<super::Entry>,
}

impl IndexV1 {
    pub fn new<R: std::io::Read>(
        reader: &mut R,
        version: super::Version,
    ) -> Result<Self, super::Error> {
        Ok(Self {
            mount_point: reader.read_string()?,
            entries: reader.read_array(|reader| super::Entry::new(reader, version))?,
        })
    }
}

pub struct IndexV2 {}
