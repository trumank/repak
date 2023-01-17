#![allow(dead_code)]
mod entry;
mod error;
mod ext;
mod footer;
mod pak;

pub use {error::*, pak::*};

pub const MAGIC: u32 = 0x5A6F12E1;

#[repr(u32)]
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Debug, strum::Display, strum::FromRepr, strum::EnumIter,
)]

pub enum Version {
    Unknown,               // v0 unknown (mostly just for padding)
    Initial,               // v1 initial specification
    NoTimestamps,          // v2 timestamps removed
    CompressionEncryption, // v3 compression and encryption support
    IndexEncryption,       // v4 index encryption support
    RelativeChunkOffsets,  // v5 offsets are relative to header
    DeleteRecords,         // v6 record deletion support
    EncryptionKeyGuid,     // v7 include key GUID
    FNameBasedCompression, // v8 compression names included
    FrozenIndex,           // v9 frozen index byte included
    PathHashIndex,         // v10
    Fnv64BugFix,           // v11
}

// strum shouldn't need to be installed by users
impl Version {
    pub fn iter() -> VersionIter {
        <Version as strum::IntoEnumIterator>::iter()
    }

    pub fn size(self) -> i64 {
        // (magic + version): u32 + (offset + size): u64 + hash: [u8; 20]
        let mut size = 4 + 4 + 8 + 8 + 20;
        if self >= Version::EncryptionKeyGuid {
            // encryption uuid: u128
            size += 16;
        }
        if self >= Version::IndexEncryption {
            // encrypted: bool
            size += 1;
        }
        if self == Version::FrozenIndex {
            // frozen index: bool
            size += 1;
        }
        if self >= Version::FNameBasedCompression {
            // compression names: [[u8; 32]; 5]
            size += 32 * 5;
        }
        size
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
