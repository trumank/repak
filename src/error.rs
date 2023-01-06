#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("illegal file magic of {0}")]
    WrongMagic(u32),
    #[error("used version {0} but pak is version {1}")]
    WrongVersion(super::Version, super::Version),
    #[error("couldn't convert {0} to boolean")]
    BoolConv(u8),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("enum conversion: {0}")]
    StrumConv(#[from] strum::ParseError),
    #[error("utf8 conversion: {0}")]
    Utf8Conv(#[from] std::string::FromUtf8Error),
    #[error("utf16 conversion: {0}")]
    Utf16Conv(#[from] std::string::FromUtf16Error),
    #[error("{0}")]
    Other(String),
}
