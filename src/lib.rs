#![allow(dead_code)]
mod entry;
mod error;
mod ext;
mod footer;
mod pak;

pub use {entry::*, error::*, ext::*, footer::*, pak::*};

pub const MAGIC: u32 = 0x5A6F12E1;

#[repr(u32)]
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Debug, strum::Display, strum::FromRepr, strum::EnumIter,
)]
pub enum Version {
    Unknown,               // unknown (mostly just for padding)
    Initial,               // initial specification
    NoTimestamps,          // timestamps removed
    CompressionEncryption, // compression and encryption support
    IndexEncryption,       // index encryption support
    RelativeChunkOffsets,  // offsets are relative to header
    DeleteRecords,         // record deletion support
    EncryptionKeyGuid,     // include key GUID
    FNameBasedCompression, // compression names included
    FrozenIndex,           // frozen index byte included
    PathHashIndex,         // more compression methods
}

// strum shouldn't need to be installed by users
impl Version {
    pub fn iter() -> VersionIter {
        <Version as strum::IntoEnumIterator>::iter()
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, strum::Display, strum::EnumString)]
pub enum Compression {
    #[default]
    None,
    Zlib,
    Gzip,
    Oodle,
}
