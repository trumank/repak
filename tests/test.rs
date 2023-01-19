fn load_pak(
    bytes: &[u8],
    key: Option<String>,
) -> Result<unpak::Pak<std::io::Cursor<&[u8]>>, unpak::Error> {
    use aes::cipher::KeyInit;
    use base64::{engine::general_purpose, Engine as _};
    let key = key
        .map(|k| {
            general_purpose::STANDARD
                .decode(k)
                .as_ref()
                .map_err(|_| unpak::Error::Base64)
                .and_then(|bytes| {
                    aes::Aes256Dec::new_from_slice(bytes).map_err(|_| unpak::Error::Aes)
                })
        })
        .transpose()?;

    for ver in unpak::Version::iter() {
        match unpak::Pak::new(std::io::Cursor::new(bytes), ver, key.clone()) {
            Ok(pak) => {
                return Ok(pak);
            }
            _ => {
                continue;
            }
        }
    }
    Err(unpak::Error::Other("version unsupported"))
}

static AES_KEY: &str = "lNJbw660IOC+kU7cnVQ1oeqrXyhk4J6UAZrCBbcnp94=";

use paste::paste;

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
                    let mut pak = load_pak(include_bytes!(concat!("packs/pack_", $version, $compress, $encrypt, $encryptindex, ".pak")), Some(AES_KEY.to_string())).unwrap();
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
        "v5" unpak::Version::RelativeChunkOffsets,
        "v7" unpak::Version::EncryptionKeyGuid,
        "v8" unpak::Version::FNameBasedCompression,
        "v9" unpak::Version::FrozenIndex,
        "v11" unpak::Version::Fnv64BugFix,
    ),
    ("", "_compress"),
    ("", "_encrypt"),
    ("", "_encryptindex")
);
