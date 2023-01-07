fn main() -> Result<(), un_pak::Error> {
    let pak = un_pak::Pak::new(
        un_pak::Version::CompressionEncryption,
        std::io::Cursor::new(include_bytes!("rando_p.pak")),
    )?;
    print!("{:#?}", pak);
    Ok(())
}
