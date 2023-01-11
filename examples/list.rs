fn main() -> Result<(), un_pak::Error> {
    let pak = un_pak::Pak::new(
        std::io::BufReader::new(std::io::Cursor::new(include_bytes!("rando_p.pak"))),
        un_pak::Version::CompressionEncryption,
    )?;
    for file in pak.entries.keys() {
        println!("{file}")
    }
    Ok(())
}
