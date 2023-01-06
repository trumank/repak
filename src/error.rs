#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("expected magic of {} but got {0}", super::MAGIC)]
    MagicMismatch(u32),
    #[error("parsed with {0} but pak was {0}")]
    VersionMismatch(super::Version, super::Version),
    #[error("expected 1 or 0 but got {0}")]
    BoolConversion(u8),
    #[error("reading file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("converting to enum: {0}")]
    StrumError(#[from] strum::ParseError),
    #[error("converting to utf8: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("converting to utf16: {0}")]
    Utf16Error(#[from] std::string::FromUtf16Error),
    #[error("{0}")]
    Other(String),
}
