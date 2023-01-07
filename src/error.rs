#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("found magic of {0:#x} instead of {:#x}", super::MAGIC)]
    WrongMagic(u32),
    #[error("used version {0} but pak is version {1}")]
    WrongVersion(super::Version, super::Version),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("enum conversion: {0}")]
    StrumConv(#[from] strum::ParseError),
    #[error("utf8 conversion: {0}")]
    Utf8Conv(#[from] std::string::FromUtf8Error),
    #[error("utf16 conversion: {0}")]
    Utf16Conv(#[from] std::string::FromUtf16Error),
    #[error("got {0}, which is not a boolean")]
    BoolConv(u8),
    #[error("{0}")]
    Other(String),
}
