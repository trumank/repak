fn main() -> Result<(), unpak::Error> {
    let pak = unpak::Pak::new(
        std::io::BufReader::new(std::io::Cursor::new(include_bytes!("rando_p.pak"))),
        unpak::Version::CompressionEncryption,
        None,
    )?;
    for file in pak.files() {
        println!("{file}");
    }
    Ok(())
}
