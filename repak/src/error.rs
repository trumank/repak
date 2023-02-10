#[derive(thiserror::Error, Debug)]
pub enum Error {
    // dependency errors
    #[error("enum conversion: {0}")]
    Strum(#[from] strum::ParseError),
    #[error("key hash is an incorrect length")]
    Aes,
    #[error("malformed base64")]
    Base64,
    // std errors
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("utf8 conversion: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("utf16 conversion: {0}")]
    Utf16(#[from] std::string::FromUtf16Error),
    #[error("bufwriter dereference: {0}")]
    IntoInner(#[from] std::io::IntoInnerError<std::io::BufWriter<Vec<u8>>>),
    // crate errors
    #[error("got {0}, which is not a boolean")]
    Bool(u8),
    #[error("found magic of {0:#x} instead of {:#x}", super::MAGIC)]
    Magic(u32),
    #[error("used version {used} but pak is version {version}")]
    Version {
        used: super::VersionMajor,
        version: super::VersionMajor,
    },
    #[error("pak is encrypted but no key was provided")]
    Encrypted,
    #[error("error with OsString")]
    OsString(std::ffi::OsString),
    #[error("{0}")]
    Other(&'static str),
}
