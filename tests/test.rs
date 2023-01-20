use paste::paste;

static AES_KEY: &str = "lNJbw660IOC+kU7cnVQ1oeqrXyhk4J6UAZrCBbcnp94=";

macro_rules! matrix_test {
    ( ($($version:literal $exp_version:expr),* $(,)?), $compress:tt, $encrypt:tt, $encryptindex:tt ) => {
        $( compress!($version, $exp_version, $compress, $encrypt, $encryptindex); )*
    };
}

macro_rules! compress {
    ( $version:literal, $exp_version:expr, ($($compress:literal),* $(,)?), $encrypt:tt, $encryptindex:tt ) => {
        $( encrypt!($version, $exp_version, $compress, $encrypt, $encryptindex); )*
    };
}

macro_rules! encrypt {
    ( $version:literal, $exp_version:expr, $compress:literal, ($($encrypt:literal),* $(,)?), $encryptindex:tt ) => {
        $( encryptindex!($version, $exp_version, $compress, $encrypt, $encryptindex); )*
    };
}

macro_rules! encryptindex {
    ( $version:literal, $exp_version:expr, $compress:literal, $encrypt:literal, ($($encryptindex:literal),* $(,)?) ) => {
        $(
            paste! {
                #[test]
                fn [< test_version_ $version $compress $encrypt $encryptindex >]() {
                    use aes::cipher::KeyInit;
                    use base64::{engine::general_purpose, Engine as _};
                    let key = general_purpose::STANDARD
                                .decode(AES_KEY)
                                .as_ref()
                                .map_err(|_| unpak::Error::Base64)
                                .and_then(|bytes| {
                                    aes::Aes256Dec::new_from_slice(bytes).map_err(|_| unpak::Error::Aes)
                                }).unwrap();
                    let mut pak = unpak::PakReader::new_any(
                        std::io::Cursor::new(include_bytes!(concat!("packs/pack_", $version, $compress, $encrypt, $encryptindex, ".pak"))),
                        Some(key),
                    ).unwrap();
                    assert_eq!(pak.mount_point(), "../mount/point/root/");
                    assert_eq!(pak.version(), $exp_version);
                    use std::collections::HashSet;
                    let files: HashSet<String> = HashSet::from_iter(pak.files());
                    assert_eq!(files, HashSet::from_iter(vec!["test.txt", "test.png", "zeros.bin", "directory/nested.txt"].into_iter().map(String::from)));

                    for file in files {
                        let mut buf = vec![];
                        let mut writer = std::io::Cursor::new(&mut buf);
                        pak.read(&file, &mut writer).unwrap();
                        match file.as_str() {
                            "test.txt" => assert_eq!(buf, include_bytes!("pack/root/test.txt"), "test.txt incorrect contents"),
                            "test.png" => assert_eq!(buf, include_bytes!("pack/root/test.png"), "test.png incorrect contents"),
                            "zeros.bin" => assert_eq!(buf, include_bytes!("pack/root/zeros.bin"), "zeros.bin incorrect contents"),
                            "directory/nested.txt" => assert_eq!(buf, include_bytes!("pack/root/directory/nested.txt"), "nested.txt incorrect contents"),
                            name => panic!("unrecognized file {}", name)
                        }
                    }
                }
            }
        )*
    };
}

matrix_test!(
    (
        "v5" unpak::Version::V5,
        "v7" unpak::Version::V7,
        "v8a" unpak::Version::V8A,
        "v8b" unpak::Version::V8B,
        "v9" unpak::Version::V9,
        "v11" unpak::Version::V11,
    ),
    ("", "_compress"),
    ("", "_encrypt"),
    ("", "_encryptindex")
);
