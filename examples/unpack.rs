fn main() -> Result<(), un_pak::Error> {
    let mut pak = un_pak::Pak::new(
        std::io::BufReader::new(std::io::Cursor::new(include_bytes!("rando_p.pak"))),
        un_pak::Version::CompressionEncryption,
        None,
    )?;
    for file in pak.files() {
        std::fs::create_dir_all(
            std::path::Path::new(&file)
                .parent()
                .expect("will be a file"),
        )?;
        match pak.get(&file).expect("file should be in pak") {
            Ok(data) => std::fs::write(&file, data)?,
            Err(e) => eprintln!("{e}"),
        }
    }
    Ok(())
}
