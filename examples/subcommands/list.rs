pub fn list(path: String, key: Option<String>) -> Result<(), unpak::Error> {
    for file in super::load_pak(path, key)?.files() {
        println!("{file}");
    }
    Ok(())
}
