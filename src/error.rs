#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("error parsing pak: {0}")]
    PakInvalid(String),
    #[error("error reading file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("error converting to enum: {0}")]
    StrumError(#[from] strum::ParseError),
}
