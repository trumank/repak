pub fn unpack(path: String, key: String) -> Result<(), unpak::Error> {
    let folder = std::path::Path::new(
        std::path::Path::new(&path)
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or_default(),
    );
    let mut pak = super::load_pak(path.clone(), key)?;
    for file in pak.files() {
        std::fs::create_dir_all(folder.join(&file).parent().expect("will be a file"))?;
        match pak.get(&file).expect("file should be in pak") {
            Ok(data) => std::fs::write(folder.join(&file), data)?,
            Err(e) => eprintln!("{e}"),
        }
    }
    Ok(())
}
