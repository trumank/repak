fn main() -> Result<(), un_pak::Error> {
    // drag onto or open any pak with the example
    let path = std::env::args().nth(1).unwrap_or_default();
    for ver in un_pak::Version::iter() {
        match un_pak::Pak::new(
            std::io::BufReader::new(std::fs::OpenOptions::new().read(true).open(&path)?),
            ver,
            None,
        ) {
            Ok(un_pak::Pak { version, .. }) | Err(un_pak::Error::Version { version, .. }) => {
                println!("{}", version);
                break;
            }
            _ => continue,
        }
    }
    // so you can read the results
    std::thread::sleep(std::time::Duration::from_secs(10));
    Ok(())
}
