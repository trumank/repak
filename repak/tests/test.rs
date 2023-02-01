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
                let r = match self.reads.read_u8() {
                    Ok(r) => {
                        self.reads.seek(SeekFrom::Current(-1)).unwrap();
                        Ok(r)
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
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
                                .map_err(|_| repak::Error::Base64)
                                .and_then(|bytes| {
                                    aes::Aes256Dec::new_from_slice(bytes).map_err(|_| repak::Error::Aes)
                                }).unwrap();


                    let mut inner_reader = std::io::Cursor::new(include_bytes!(concat!("packs/pack_", $version, $compress, $encrypt, $encryptindex, ".pak")));
                    let len = inner_reader.seek(SeekFrom::End(0)).unwrap();

                    let mut pak = repak::PakReader::new_any(
                        ReadCounter::new_size(inner_reader, len as usize),
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
                        pak.read_file(&file, &mut writer).unwrap();
                        match file.as_str() {
                            "test.txt" => assert_eq!(buf, include_bytes!("pack/root/test.txt"), "test.txt incorrect contents"),
                            "test.png" => assert_eq!(buf, include_bytes!("pack/root/test.png"), "test.png incorrect contents"),
                            "zeros.bin" => assert_eq!(buf, include_bytes!("pack/root/zeros.bin"), "zeros.bin incorrect contents"),
                            "directory/nested.txt" => assert_eq!(buf, include_bytes!("pack/root/directory/nested.txt"), "nested.txt incorrect contents"),
                            name => panic!("unrecognized file {}", name)
                        }
                    }

                    for r in pak.into_reader().into_reads() {
                        // sanity check. a pak file can be constructed with a lot of dead space
                        // which wouldn't have to be read, but so far all bytes in paks generated
                        // by UnrealPak are meaningful
                        assert!(r > 0, "every byte has been read at least once");
                    }
                }
            }
        )*
    };
}

matrix_test!(
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
    ("", "_encryptindex")
);
