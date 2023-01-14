pub fn version(path: String, key: String) -> Result<(), unpak::Error> {
    println!("{}", super::load_pak(path, key)?.version());
    Ok(())
}
