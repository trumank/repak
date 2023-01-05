#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("expected magic of {} but found {0}", super::MAGIC)]
    MagicMismatch(u32),
    #[error("parsed with {0} but pak was {0}")]
    VersionMismatch(super::Version, super::Version),
    #[error("error reading file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("error converting enum: {0}")]
    StrumError(#[from] strum::ParseError),
    #[error("error converting to utf8: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("error converting to utf16: {0}")]
    Utf16Error(#[from] std::string::FromUtf16Error),
    #[error("{0}")]
    Other(String),
}
