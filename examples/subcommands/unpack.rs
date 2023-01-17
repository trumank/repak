pub fn unpack(path: String, key: Option<String>) -> Result<(), unpak::Error> {
    let folder = std::path::Path::new(
        std::path::Path::new(&path)
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or_default(),
    );
    let mut pak = super::load_pak(path.clone(), key)?;
    for file in pak.files() {
        std::fs::create_dir_all(folder.join(&file).parent().expect("will be a file"))?;
        match pak.read(&file, &mut std::fs::File::create(folder.join(&file))?) {
            Ok(_) => println!("{file}"),
            Err(e) => eprintln!("{e}"),
        }
    }
    Ok(())
}
