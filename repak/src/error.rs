use crate::Compression;

#[derive(thiserror::Error)]
pub enum Error {
    // dependency errors
    #[error("enum conversion: {0}")]
    Strum(#[from] strum::ParseError),

    #[error("expect 256 bit AES key as base64 or hex string")]
    Aes,

    // feature errors
    #[error("enable the compression feature to read compressed paks")]
    Compression,

    #[error("enable the encryption feature to read encrypted paks")]
    Encryption,

    #[error("enable the oodle feature to read Oodle compressed paks")]
    Oodle,

    // std errors
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("fmt error: {0}")]
    Fmt(#[from] std::fmt::Error),

    #[error("utf8 conversion: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("utf16 conversion: {0}")]
    Utf16(#[from] std::string::FromUtf16Error),

    #[error("bufwriter dereference: {0}")]
    IntoInner(#[from] std::io::IntoInnerError<std::io::BufWriter<Vec<u8>>>),

    // crate errors
    #[error("got {0}, which is not a boolean")]
    Bool(u8),

    #[error("found magic of {:#x} instead of {:#x}", .0, super::MAGIC)]
    Magic(u32),

    #[cfg(feature = "oodle")]
    #[error("Oodle loader error: {0}")]
    OodleFailed(#[from] oodle_loader::Error),

    #[error("No entry found at {0}")]
    MissingEntry(String),

    #[error("Prefix \"{prefix}\" does not match path \"{path}\"")]
    PrefixMismatch { prefix: String, path: String },

    #[error("Attempted to write to \"{0}\" which is outside of output directory")]
    WriteOutsideOutput(String),

    #[error("Output directory is not empty: \"{0}\"")]
    OutputNotEmpty(String),

    #[error("Input is not a directory: \"{0}\"")]
    InputNotADirectory(String),

    #[error("{0} decompression failed")]
    DecompressionFailed(Compression),

    #[error("used version {used} but pak is version {version}")]
    Version {
        used: super::VersionMajor,
        version: super::VersionMajor,
    },

    #[error("pak is encrypted but no key was provided")]
    Encrypted,

    #[error("error with OsString")]
    OsString(std::ffi::OsString),

    #[error("{0}version unsupported or is encrypted (possibly missing --aes-key?)")]
    UnsupportedOrEncrypted(String),

    #[error("{0}")]
    Other(String),
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
