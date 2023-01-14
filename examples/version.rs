fn main() -> Result<(), unpak::Error> {
    // drag onto or open any pak with the example
    let path = std::env::args().nth(1).unwrap_or_default();
    for ver in unpak::Version::iter() {
        match unpak::Pak::new(
            std::io::BufReader::new(std::fs::OpenOptions::new().read(true).open(&path)?),
            ver,
            None,
        ) {
            Ok(pak) => {
                println!("{}", pak.version());
                break;
            }
            Err(unpak::Error::Version { version, .. }) => {
                println!("{version}");
                break;
            }
            _ => continue,
        }
    }
    // so you can read the results
    std::thread::sleep(std::time::Duration::from_secs(10));
    Ok(())
}
