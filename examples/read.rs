fn main() -> Result<(), un_pak::Error> {
    let path = std::env::args().nth(1).unwrap_or_default();
    for version in un_pak::Version::iter() {
        print!("{version} - ");
        match un_pak::Pak::new(
            version,
            std::io::BufReader::new(std::fs::OpenOptions::new().read(true).open(&path)?),
        ) {
            Ok(pak) => {
                print!("{:#?}", pak);
                println!("parsed successfully!");
            }
            Err(e) => println!("{e}"),
        }
    }
    std::thread::sleep_ms(10000);
    Ok(())
}
