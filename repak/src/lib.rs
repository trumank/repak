#![allow(dead_code)]
mod entry;
mod error;
mod ext;
mod footer;
mod pak;

pub use {error::*, pak::*};

pub const MAGIC: u32 = 0x5A6F12E1;

#[cfg(feature = "oodle")]
static mut OODLE: Option<once_cell::sync::Lazy<OodleDecompress>> = None;

#[cfg(feature = "oodle")]
type OodleDecompress = fn(comp_buf: &[u8], raw_buf: &mut [u8]) -> i32;

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Debug,
    strum::Display,
    strum::FromRepr,
    strum::EnumIter,
    strum::EnumString,
    strum::EnumVariantNames,
)]
pub enum Version {
    V0,
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
    V7,
    V8A,
    V8B,
    V9,
    V10,
    V11,
}

#[repr(u32)]
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Debug, strum::Display, strum::FromRepr, strum::EnumIter,
)]
/// Version actually written to the pak file
pub enum VersionMajor {
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
    pub fn iter() -> std::iter::Rev<VersionIter> {
        <Version as strum::IntoEnumIterator>::iter().rev()
    }

    pub fn size(self) -> i64 {
        // (magic + version): u32 + (offset + size): u64 + hash: [u8; 20]
        let mut size = 4 + 4 + 8 + 8 + 20;
        if self.version_major() >= VersionMajor::EncryptionKeyGuid {
            // encryption uuid: u128
            size += 16;
        }
        if self.version_major() >= VersionMajor::IndexEncryption {
            // encrypted: bool
            size += 1;
        }
        if self.version_major() == VersionMajor::FrozenIndex {
            // frozen index: bool
            size += 1;
        }
        if self >= Version::V8A {
            // compression names: [[u8; 32]; 4]
            size += 32 * 4;
        }
        if self >= Version::V8B {
            // additional compression name
            size += 32;
        }
        size
    }

    /// Losslessly convert full version into major version
    pub fn version_major(&self) -> VersionMajor {
        match self {
            Version::V0 => VersionMajor::Unknown,
            Version::V1 => VersionMajor::Initial,
            Version::V2 => VersionMajor::NoTimestamps,
            Version::V3 => VersionMajor::CompressionEncryption,
            Version::V4 => VersionMajor::IndexEncryption,
            Version::V5 => VersionMajor::RelativeChunkOffsets,
            Version::V6 => VersionMajor::DeleteRecords,
            Version::V7 => VersionMajor::EncryptionKeyGuid,
            Version::V8A => VersionMajor::FNameBasedCompression,
            Version::V8B => VersionMajor::FNameBasedCompression,
            Version::V9 => VersionMajor::FrozenIndex,
            Version::V10 => VersionMajor::PathHashIndex,
            Version::V11 => VersionMajor::Fnv64BugFix,
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, strum::Display, strum::EnumString)]
pub enum Compression {
    #[default]
    None,
    Zlib,
    Gzip,
    Oodle,
    Zstd,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum Key {
    #[cfg(feature = "encryption")]
    Some(aes::Aes256),
    None,
}

#[cfg(feature = "encryption")]
impl From<aes::Aes256> for Key {
    fn from(value: aes::Aes256) -> Self {
        Self::Some(value)
    }
}

#[cfg(feature = "oodle")]
pub(crate) enum Oodle<'func> {
    Some(&'func OodleDecompress),
    None,
}

#[cfg(not(feature = "oodle"))]
pub(crate) enum Oodle {
    None,
}
