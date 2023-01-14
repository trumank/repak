mod list;
mod unpack;
mod version;
pub use {list::list, unpack::unpack, version::version};

fn load_pak(
    path: String,
    key: String,
) -> Result<unpak::Pak<std::io::BufReader<std::fs::File>>, unpak::Error> {
    for ver in unpak::Version::iter() {
        match unpak::Pak::new(
            std::io::BufReader::new(std::fs::OpenOptions::new().read(true).open(&path)?),
            ver,
            match key.as_bytes() {
                &[] => None,
                key => Some(key),
            },
        ) {
            Ok(pak) => {
                return Ok(pak);
            }
            _ => continue,
        }
    }
    Err(unpak::Error::Other("version unsupported"))
}
