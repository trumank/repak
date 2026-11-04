#![cfg(feature = "default")]
use byteorder::{ReadBytesExt, WriteBytesExt};
use paste::paste;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

/// A reader that tracks how many times bytes in the inner reader been read. Useful to check read coverage.
#[derive(Debug)]
pub struct ReadCounter<T> {
    inner: T,
    reads: io::Cursor<Vec<u8>>,
}

impl<T> ReadCounter<T> {
    pub fn new(inner: T) -> Self {
        ReadCounter {
            inner,
            reads: Cursor::new(vec![]),
        }
    }
    pub fn new_size(inner: T, size: usize) -> Self {
        ReadCounter {
            inner,
            reads: Cursor::new(vec![0; size]),
        }
    }
    pub fn into_reads(self) -> Vec<u8> {
        self.reads.into_inner()
    }
}

impl<T> Seek for ReadCounter<T>
where
    T: Seek,
{
    fn seek(&mut self, style: SeekFrom) -> io::Result<u64> {
        self.reads.seek(style).unwrap();
        self.inner.seek(style)
    }
}

impl<T> Read for ReadCounter<T>
where
    T: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf);
        if let Ok(read) = read {
            for _ in 0..read {
                let save = self.reads.position();
                let r = match self.reads.read_u8() {
                    Ok(r) => {
                        self.reads.seek(SeekFrom::Current(-1)).unwrap();
                        Ok(r)
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        // since rust 1.80 read_exact will move cursor position to end of internal
                        // buffer so we have to reset it
                        // ref https://github.com/rust-lang-ci/rust/commit/67b37f5054e4508694b7bd0b766e27f64cbd2d7f
                        self.reads.seek(SeekFrom::Start(save)).unwrap();
                        Ok(0)
                    }
                    Err(e) => Err(e),
                }
                .unwrap();
                self.reads.write_u8(r + 1).unwrap();
            }
        }
        read
    }
}

mod test {
    #[test]
    fn test_read_counter() {
        use byteorder::{ReadBytesExt, LE};
        use std::io::{Cursor, Seek, SeekFrom};

        let source = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut proxy = super::ReadCounter::new(source);

        proxy.seek(SeekFrom::Start(3)).unwrap();
        proxy.read_u8().unwrap();
        proxy.seek(SeekFrom::Current(-1)).unwrap();
        proxy.read_u8().unwrap();
        proxy.read_u16::<LE>().unwrap();

        assert_eq!(proxy.reads.into_inner(), vec![0, 0, 0, 2, 1, 1]);
    }
}

static AES_KEY: &str = "lNJbw660IOC+kU7cnVQ1oeqrXyhk4J6UAZrCBbcnp94=";

fn test_read(version: repak::Version, _file_name: &str, bytes: &[u8]) {
    use aes::cipher::KeyInit;
    use base64::{engine::general_purpose, Engine as _};
    let key = general_purpose::STANDARD
        .decode(AES_KEY)
        .as_ref()
        .map_err(|_| repak::Error::Aes)
        .and_then(|bytes| aes::Aes256::new_from_slice(bytes).map_err(|_| repak::Error::Aes))
        .unwrap();

    let mut inner_reader = std::io::Cursor::new(bytes);
    let len = inner_reader.seek(SeekFrom::End(0)).unwrap();
    let mut reader = ReadCounter::new_size(inner_reader, len as usize);

    let pak = repak::PakBuilder::new()
        .key(key)
        .reader(&mut reader)
        .unwrap();

    assert_eq!(pak.mount_point(), "../mount/point/root/");
    assert_eq!(pak.version(), version);
    use std::collections::HashSet;
    let files: HashSet<String> = HashSet::from_iter(pak.files());
    assert_eq!(
        files,
        HashSet::from_iter(
            vec!["test.txt", "test.png", "zeros.bin", "directory/nested.txt"]
                .into_iter()
                .map(String::from)
        )
    );

    for file in files {
        let mut buf = vec![];
        let mut writer = std::io::Cursor::new(&mut buf);
        pak.read_file(&file, &mut reader, &mut writer).unwrap();
        match file.as_str() {
            "test.txt" => assert_eq!(
                buf,
                include_bytes!("pack/root/test.txt"),
                "test.txt incorrect contents"
            ),
            "test.png" => assert_eq!(
                buf,
                include_bytes!("pack/root/test.png"),
                "test.png incorrect contents"
            ),
            "zeros.bin" => assert_eq!(
                buf,
                include_bytes!("pack/root/zeros.bin"),
                "zeros.bin incorrect contents"
            ),
            "directory/nested.txt" => assert_eq!(
                buf,
                include_bytes!("pack/root/directory/nested.txt"),
                "nested.txt incorrect contents"
            ),
            name => panic!("unrecognized file {}", name),
        }
    }

    for r in reader.into_reads() {
        // sanity check. a pak file can be constructed with a lot of dead space
        // which wouldn't have to be read, but so far all bytes in paks generated
        // by UnrealPak are meaningful
        assert!(r > 0, "every byte has been read at least once");
    }
}

/// Compares paks by decoded content, for when their padding bytes differ
fn assert_pak_content_equal(key: aes::Aes256, original: &[u8], rewritten: &[u8]) {
    let mut original_reader = std::io::Cursor::new(original);
    let original_pak = repak::PakBuilder::new()
        .key(key.clone())
        .reader(&mut original_reader)
        .unwrap();

    let mut rewritten_reader = std::io::Cursor::new(rewritten);
    let rewritten_pak = repak::PakBuilder::new()
        .key(key)
        .reader(&mut rewritten_reader)
        .unwrap();

    assert_eq!(original_pak.mount_point(), rewritten_pak.mount_point());
    use std::collections::HashSet;
    let original_files: HashSet<String> = HashSet::from_iter(original_pak.files());
    let rewritten_files: HashSet<String> = HashSet::from_iter(rewritten_pak.files());
    assert_eq!(original_files, rewritten_files);

    for path in original_files {
        let original_data = original_pak.get(&path, &mut original_reader).unwrap();
        let rewritten_data = rewritten_pak.get(&path, &mut rewritten_reader).unwrap();
        assert_eq!(original_data, rewritten_data, "{path} contents differ");
    }
}

/// Whether a fixture's file data is encrypted (`_encrypt`, not only `_encryptindex`)
fn has_encrypted_data(file_name: &str) -> bool {
    file_name.contains("_encrypt.") || file_name.contains("_encrypt_")
}

fn test_write(version: repak::Version, file_name: &str, bytes: &[u8]) {
    use aes::cipher::KeyInit;
    use base64::{engine::general_purpose, Engine as _};
    let key = general_purpose::STANDARD
        .decode(AES_KEY)
        .as_ref()
        .map_err(|_| repak::Error::Aes)
        .and_then(|bytes| aes::Aes256::new_from_slice(bytes).map_err(|_| repak::Error::Aes))
        .unwrap();

    let mut reader = std::io::Cursor::new(bytes);
    let pak_reader = repak::PakBuilder::new()
        .key(key.clone())
        .reader(&mut reader)
        .unwrap();

    let encrypted_data = has_encrypted_data(file_name);
    let writer = Cursor::new(vec![]);
    let mut pak_writer = repak::PakBuilder::new()
        .key(key.clone())
        .encrypt_index(pak_reader.encrypted_index())
        .encrypt_data(encrypted_data)
        .writer(
            writer,
            pak_reader.version(),
            pak_reader.mount_point().to_owned(),
            pak_reader.path_hash_seed(),
        );

    for path in pak_reader.files() {
        let data = pak_reader.get(&path, &mut reader).unwrap();
        pak_writer.write_file(&path, false, data).unwrap();
    }

    let rewrite = pak_writer.write_index().unwrap().into_inner();
    if encrypted_data && version == repak::Version::V5 {
        // UnrealPak 4.20 pads encrypted data with random bytes
        assert_eq!(rewrite.len(), bytes.len());
        assert_pak_content_equal(key, bytes, &rewrite);
    } else {
        assert!(rewrite == reader.into_inner());
    }
}

fn test_rewrite_index(_version: repak::Version, _file_name: &str, bytes: &[u8]) {
    use aes::cipher::KeyInit;
    use base64::{engine::general_purpose, Engine as _};
    let key = general_purpose::STANDARD
        .decode(AES_KEY)
        .as_ref()
        .map_err(|_| repak::Error::Aes)
        .and_then(|bytes| aes::Aes256::new_from_slice(bytes).map_err(|_| repak::Error::Aes))
        .unwrap();

    let mut buf = std::io::Cursor::new(bytes.to_vec());
    let pak_reader = repak::PakBuilder::new().key(key).reader(&mut buf).unwrap();

    let rewrite = pak_reader
        .into_pakwriter(buf)
        .unwrap()
        .write_index()
        .unwrap()
        .into_inner();

    assert!(bytes == rewrite);
}

fn test_rewrite_add_file(_version: repak::Version, file_name: &str, bytes: &[u8]) {
    use aes::cipher::KeyInit;
    use base64::{engine::general_purpose, Engine as _};
    let key = general_purpose::STANDARD
        .decode(AES_KEY)
        .as_ref()
        .map_err(|_| repak::Error::Aes)
        .and_then(|bytes| aes::Aes256::new_from_slice(bytes).map_err(|_| repak::Error::Aes))
        .unwrap();

    const MARKER: &[u8] = b"plaintext marker for a file added on rewrite";

    let mut buf = std::io::Cursor::new(bytes.to_vec());
    let pak_reader = repak::PakBuilder::new()
        .key(key.clone())
        .reader(&mut buf)
        .unwrap();
    let mut pak_writer = pak_reader.into_pakwriter(buf).unwrap();
    pak_writer.write_file("added.txt", false, MARKER).unwrap();
    let rewrite = pak_writer.write_index().unwrap().into_inner();

    // a file added on rewrite is encrypted only if the source pak's data was
    let data_encrypted = has_encrypted_data(file_name);
    let plaintext_found = rewrite.windows(MARKER.len()).any(|w| w == MARKER);
    assert_eq!(plaintext_found, !data_encrypted);

    let mut reader = std::io::Cursor::new(rewrite);
    let pak_reader = repak::PakBuilder::new()
        .key(key)
        .reader(&mut reader)
        .unwrap();
    assert_eq!(pak_reader.get("added.txt", &mut reader).unwrap(), MARKER);
}

macro_rules! matrix_test {
    ( $name:literal, ($($version:literal $exp_version:expr),* $(,)?), $compress:tt, $encrypt:tt, $encryptindex:tt, $body:tt ) => {
        $( matrix_test_compress!($name, $version, $exp_version, $compress, $encrypt, $encryptindex, $body); )*
    };
}

macro_rules! matrix_test_compress {
    ( $name:literal, $version:literal, $exp_version:expr, ($($compress:literal),* $(,)?), $encrypt:tt, $encryptindex:tt, $body:tt ) => {
        $( matrix_test_encrypt!($name, $version, $exp_version, $compress, $encrypt, $encryptindex, $body); )*
    };
}

macro_rules! matrix_test_encrypt {
    ( $name:literal, $version:literal, $exp_version:expr, $compress:literal, ($($encrypt:literal),* $(,)?), $encryptindex:tt, $body:tt ) => {
        $( matrix_test_encryptindex!($name, $version, $exp_version, $compress, $encrypt, $encryptindex, $body); )*
    };
}

macro_rules! matrix_test_encryptindex {
    ( $name:literal, $version:literal, $exp_version:expr, $compress:literal, $encrypt:literal, ($($encryptindex:literal),* $(,)?), $body:tt ) => {
        $( matrix_test_body!($name, $version, $exp_version, $compress, $encrypt, $encryptindex, $body); )*
    };
}

macro_rules! matrix_test_body {
    ( $name:literal, $version:literal, $exp_version:expr, $compress:literal, $encrypt:literal, $encryptindex:literal, $body:expr ) => {
        paste! {
            #[test]
            fn [< test_ $name _version_ $version $compress $encrypt $encryptindex >]() {
                $body(
                    $exp_version,
                    concat!("pack_", $version, $compress, $encrypt, $encryptindex, ".pak"),
                    include_bytes!(concat!("packs/pack_", $version, $compress, $encrypt, $encryptindex, ".pak")));
            }
        }
    };
}

matrix_test!(
    "read",
    (
        "v5" repak::Version::V5,
        "v7" repak::Version::V7,
        "v8a" repak::Version::V8A,
        "v8b" repak::Version::V8B,
        "v9" repak::Version::V9,
        "v11" repak::Version::V11,
    ),
    ("", "_compress"),
    ("", "_encrypt"),
    ("", "_encryptindex"),
    test_read
);

matrix_test!(
    "write",
    (
        "v5" repak::Version::V5,
        "v7" repak::Version::V7,
        "v8a" repak::Version::V8A,
        "v8b" repak::Version::V8B,
        "v9" repak::Version::V9,
        "v11" repak::Version::V11,
    ),
    ("", /*"_compress"*/),
    ("", "_encrypt"),
    ("", "_encryptindex"),
    test_write
);

matrix_test!(
    "rewrite_index",
    (
        "v5" repak::Version::V5,
        "v7" repak::Version::V7,
        "v8a" repak::Version::V8A,
        "v8b" repak::Version::V8B,
        "v9" repak::Version::V9,
        "v11" repak::Version::V11,
    ),
    ("", "_compress"),
    ("", "_encrypt"),
    ("", "_encryptindex"),
    test_rewrite_index
);

matrix_test!(
    "rewrite_add_file",
    (
        "v5" repak::Version::V5,
        "v7" repak::Version::V7,
        "v8a" repak::Version::V8A,
        "v8b" repak::Version::V8B,
        "v9" repak::Version::V9,
        "v11" repak::Version::V11,
    ),
    ("", "_compress"),
    ("", "_encrypt"),
    ("", "_encryptindex"),
    test_rewrite_add_file
);

mod roundtrip {
    use std::io::Cursor;

    const FILE_CONTENTS: &[(&str, &[u8])] = &[
        ("hello.txt", b"Hello, world!"),
        ("empty.txt", b""),
        ("large.bin", &[0xAB; 4096]),
        ("dir/nested.txt", b"nested file content"),
    ];

    fn roundtrip(version: repak::Version, compression: Option<repak::Compression>) {
        let allowed_compression: Vec<repak::Compression> = compression.into_iter().collect();

        let writer = Cursor::new(vec![]);
        let mut builder = repak::PakBuilder::new();
        if !allowed_compression.is_empty() {
            builder = builder.compression(allowed_compression);
        }
        let mut pak_writer = builder.writer(writer, version, "../../../".to_string(), Some(0));

        for (path, data) in FILE_CONTENTS {
            pak_writer
                .write_file(path, compression.is_some(), *data)
                .unwrap();
        }

        let buf = pak_writer.write_index().unwrap().into_inner();

        let mut reader = Cursor::new(&buf);
        let pak_reader = repak::PakBuilder::new().reader(&mut reader).unwrap();

        assert_eq!(pak_reader.version(), version);
        assert_eq!(pak_reader.mount_point(), "../../../");

        let mut files: Vec<String> = pak_reader.files();
        files.sort();
        let mut expected: Vec<String> = FILE_CONTENTS.iter().map(|(p, _)| p.to_string()).collect();
        expected.sort();
        assert_eq!(files, expected);

        for (path, expected_data) in FILE_CONTENTS {
            let data = pak_reader.get(path, &mut reader).unwrap();
            assert_eq!(
                data, *expected_data,
                "mismatched content for {} with version {:?} compression {:?}",
                path, version, compression,
            );
        }
    }

    #[test]
    fn roundtrip_encrypted() {
        use aes::cipher::KeyInit;
        let key = aes::Aes256::new_from_slice(&[7; 32]).unwrap();
        let files: &[(&str, &[u8])] = &[
            ("hello.txt", b"Hello, world!"),
            ("empty.txt", b""),
            ("multi_block.txt", &b"0123456789abcdef".repeat(20000)),
        ];

        for version in [
            repak::Version::V5,
            repak::Version::V7,
            repak::Version::V8A,
            repak::Version::V8B,
            repak::Version::V9,
            repak::Version::V11,
        ] {
            for compress in [false, true] {
                let mut pak_writer = repak::PakBuilder::new()
                    .key(key.clone())
                    .compression([repak::Compression::Zlib])
                    .writer(Cursor::new(vec![]), version, "../../../".to_string(), None);
                let entry_builder = pak_writer.entry_builder();
                for (path, data) in files {
                    let entry = entry_builder.build_entry(compress, *data).unwrap();
                    pak_writer.write_entry(path.to_string(), entry).unwrap();
                }
                let buf = pak_writer.write_index().unwrap().into_inner();

                assert!(!buf.windows(13).any(|w| w == b"Hello, world!"));
                assert!(repak::PakBuilder::new()
                    .reader(&mut Cursor::new(&buf))
                    .is_err());

                let mut reader = Cursor::new(&buf);
                let pak_reader = repak::PakBuilder::new()
                    .key(key.clone())
                    .reader(&mut reader)
                    .unwrap();
                assert_eq!(pak_reader.version(), version);
                for (path, expected_data) in files {
                    let data = pak_reader.get(path, &mut reader).unwrap();
                    assert!(
                        data == *expected_data,
                        "mismatched content for {path} with version {version:?} compress {compress}",
                    );
                }
            }
        }
    }

    #[test]
    fn roundtrip_encrypted_old_versions() {
        use aes::cipher::KeyInit;
        let key = aes::Aes256::new_from_slice(&[7; 32]).unwrap();
        let data: &[u8] = b"Hello, world!";

        // a key encrypts only what the pak version supports
        for (version, data_encrypted, index_encrypted) in [
            (repak::Version::V1, false, false),
            (repak::Version::V2, false, false),
            (repak::Version::V3, true, false),
            (repak::Version::V4, true, true),
        ] {
            let mut pak_writer = repak::PakBuilder::new().key(key.clone()).writer(
                Cursor::new(vec![]),
                version,
                "../../../".to_string(),
                None,
            );
            pak_writer.write_file("hello.txt", false, data).unwrap();
            let buf = pak_writer.write_index().unwrap().into_inner();

            let plaintext_found = buf.windows(data.len()).any(|w| w == data);
            assert_eq!(plaintext_found, !data_encrypted, "{version:?}");

            let mut reader = Cursor::new(&buf);
            let pak_reader = repak::PakBuilder::new()
                .key(key.clone())
                .reader(&mut reader)
                .unwrap();
            assert_eq!(pak_reader.encrypted_index(), index_encrypted, "{version:?}");
            assert_eq!(pak_reader.get("hello.txt", &mut reader).unwrap(), data);
        }
    }

    macro_rules! roundtrip_tests {
        (pre_fname: $($version:ident),+ $(,)?) => {
            $(
                paste::paste! {
                    #[test]
                    fn [< roundtrip_ $version:lower _none >]() {
                        roundtrip(repak::Version::$version, None);
                    }

                    #[test]
                    fn [< roundtrip_ $version:lower _zlib >]() {
                        roundtrip(repak::Version::$version, Some(repak::Compression::Zlib));
                    }

                    #[test]
                    fn [< roundtrip_ $version:lower _gzip >]() {
                        roundtrip(repak::Version::$version, Some(repak::Compression::Gzip));
                    }
                }
            )+
        };
        (fname: $($version:ident),+ $(,)?) => {
            $(
                paste::paste! {
                    #[test]
                    fn [< roundtrip_ $version:lower _none >]() {
                        roundtrip(repak::Version::$version, None);
                    }

                    #[test]
                    fn [< roundtrip_ $version:lower _zlib >]() {
                        roundtrip(repak::Version::$version, Some(repak::Compression::Zlib));
                    }

                    #[test]
                    fn [< roundtrip_ $version:lower _gzip >]() {
                        roundtrip(repak::Version::$version, Some(repak::Compression::Gzip));
                    }

                    #[test]
                    fn [< roundtrip_ $version:lower _zstd >]() {
                        roundtrip(repak::Version::$version, Some(repak::Compression::Zstd));
                    }

                    #[test]
                    fn [< roundtrip_ $version:lower _lz4 >]() {
                        roundtrip(repak::Version::$version, Some(repak::Compression::LZ4));
                    }
                }
            )+
        };
    }

    roundtrip_tests!(pre_fname: V5, V7);
    roundtrip_tests!(fname: V8A, V8B, V9, V11);
}
