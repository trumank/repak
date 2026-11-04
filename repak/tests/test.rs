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

fn test_write(_version: repak::Version, _file_name: &str, bytes: &[u8]) {
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
        .key(key)
        .reader(&mut reader)
        .unwrap();

    let writer = Cursor::new(vec![]);
    let mut pak_writer = repak::PakBuilder::new().writer(
        writer,
        pak_reader.version(),
        pak_reader.mount_point().to_owned(),
        Some(0x205C5A7D),
    );

    for path in pak_reader.files() {
        let data = pak_reader.get(&path, &mut reader).unwrap();
        pak_writer.write_file(&path, false, data).unwrap();
    }

    assert!(pak_writer.write_index().unwrap().into_inner() == reader.into_inner());
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

#[test]
fn test_rewrite_keeps_encryption_guid() {
    const GUID: u128 = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;

    let mut bytes = include_bytes!("packs/pack_v11.pak").to_vec();
    // the footer is: encryption guid, encrypted flag, magic
    let magic = bytes
        .windows(4)
        .rposition(|w| w == repak::MAGIC.to_le_bytes())
        .unwrap();
    bytes[magic - 17..magic - 1].copy_from_slice(&GUID.to_le_bytes());

    let mut buf = std::io::Cursor::new(bytes);
    let pak_reader = repak::PakBuilder::new().reader(&mut buf).unwrap();
    assert_eq!(pak_reader.encryption_guid(), Some(GUID));

    let mut rewrite = std::io::Cursor::new(
        pak_reader
            .into_pakwriter(buf)
            .unwrap()
            .write_index()
            .unwrap()
            .into_inner(),
    );
    let pak_reader = repak::PakBuilder::new().reader(&mut rewrite).unwrap();
    assert_eq!(pak_reader.encryption_guid(), Some(GUID));
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
    ("", /*"_encrypt"*/),
    ("", /*"_encryptindex"*/),
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
    ("", /*"_encryptindex"*/),
    test_rewrite_index
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
