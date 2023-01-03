#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("error parsing pak: {0}")]
    PakInvalid(String),
    #[error("error reading file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("error converting to enum: {0}")]
    StrumError(#[from] strum::ParseError),
    #[error("error converting to utf8: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("error converting to utf16: {0}")]
    Utf16Error(#[from] std::string::FromUtf16Error),
}
