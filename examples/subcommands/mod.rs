mod list;
mod unpack;
mod version;
pub use {list::list, unpack::unpack, version::version};

fn load_pak(
    path: String,
    key: Option<String>,
) -> Result<unpak::Pak<std::io::BufReader<std::fs::File>>, unpak::Error> {
    use aes::cipher::KeyInit;
    use base64::{engine::general_purpose, Engine as _};
    let key = key
        .map(|k| {
            general_purpose::STANDARD
                .decode(k)
                .as_ref()
                .map_err(|_| unpak::Error::Base64)
                .and_then(|bytes| {
                    aes::Aes256Dec::new_from_slice(bytes).map_err(|_| unpak::Error::Aes)
                })
        })
        .transpose()?;

    for ver in unpak::Version::iter() {
        match unpak::Pak::new(
            std::io::BufReader::new(std::fs::OpenOptions::new().read(true).open(&path)?),
            ver,
            key.clone(),
        ) {
            Ok(pak) => {
                return Ok(pak);
            }
            _ => continue,
        }
    }
    Err(unpak::Error::Other("version unsupported"))
}
