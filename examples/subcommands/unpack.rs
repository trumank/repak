pub fn unpack(path: String, key: String) -> Result<(), unpak::Error> {
    let folder = std::path::Path::new(
        std::path::Path::new(&path)
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or_default(),
    );
    let mut pak = super::load_pak(path.clone(), key)?;
    std::thread::scope(|scope| -> Result<(), unpak::Error> {
        for file in pak.files() {
            match pak.get(&file).expect("file should be in pak") {
                Ok(data) => {
                    scope.spawn(move || -> Result<(), unpak::Error> {
                        std::fs::create_dir_all(
                            folder.join(&file).parent().expect("will be a file"),
                        )?;
                        println!("{file}");
                        std::fs::write(folder.join(&file), data)?;
                        Ok(())
                    });
                }
                Err(e) => eprintln!("{e}"),
            }
        }
        Ok(())
    })
}
