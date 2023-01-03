#![allow(dead_code)]
mod error;
mod ext;
mod footer;
mod pakentry;
mod pakfile;

pub use {error::*, ext::*, footer::*, pakentry::*, pakfile::*};

pub const MAGIC: u32 = 0x5A6F12E1;

#[repr(u32)]
#[derive(
    Default,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Debug,
    strum::Display,
    strum::FromRepr,
    strum::EnumIter,
)]
pub enum Version {
    Unknown,               // unknown (mostly just for padding :p)
    Initial,               // initial specification
    NoTimestamps,          // timestamps removed
    CompressionEncryption, // compression and encryption support
    IndexEncryption,       // index encryption support
    RelativeChunkOffsets,  // offsets are relative to header
    DeleteRecords,         // record deletion support
    EncryptionKeyGuid,     // include key GUID
    FNameBasedCompression, // compression names included
    FrozenIndex,           // frozen index byte included
    #[default]
    PathHashIndex, // more compression methods
}

// i don't want people to need to install strum
impl Version {
    pub fn iter() -> VersionIter {
        <Version as strum::IntoEnumIterator>::iter()
    }
}

#[derive(Copy, Clone, Debug, strum::Display, strum::EnumString)]
pub enum Compression {
    Zlib,
    Gzip,
    Oodle,
}
