fn main() -> Result<(), un_pak::Error> {
    for version in un_pak::Version::iter().rev() {
        match un_pak::Pak::new(version, std::io::Cursor::new(include_bytes!("rando_p.pak"))) {
            Ok(_) => {
                println!("parsed successfully!");
                return Ok(());
            }
            Err(e) => println!("{e}"),
        }
    }
    Err(un_pak::Error::Other("no version can parse".to_string()))
}
