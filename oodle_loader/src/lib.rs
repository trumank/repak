use std::{
    io::{Read, Write},
    sync::OnceLock,
};

type Result<T, E = Error> = std::result::Result<T, E>;

pub use oodle_lz::{CompressionLevel, Compressor};

mod oodle_lz {
    #[derive(Debug, Clone, Copy)]
    #[repr(i32)]
    pub enum Compressor {
        /// None = memcpy, pass through uncompressed bytes
        None = 3,

        /// Fast decompression and high compression ratios, amazing!
        Kraken = 8,
        /// Leviathan = Kraken's big brother with higher compression, slightly slower decompression.
        Leviathan = 13,
        /// Mermaid is between Kraken & Selkie - crazy fast, still decent compression.
        Mermaid = 9,
        /// Selkie is a super-fast relative of Mermaid.  For maximum decode speed.
        Selkie = 11,
        /// Hydra, the many-headed beast = Leviathan, Kraken, Mermaid, or Selkie (see $OodleLZ_About_Hydra)
        Hydra = 12,
    }

    #[derive(Debug, Clone, Copy)]
    #[repr(i32)]
    pub enum CompressionLevel {
        /// don't compress, just copy raw bytes
        None = 0,
        /// super fast mode, lower compression ratio
        SuperFast = 1,
        /// fastest LZ mode with still decent compression ratio
        VeryFast = 2,
        /// fast - good for daily use
        Fast = 3,
        /// standard medium speed LZ mode
        Normal = 4,

        /// optimal parse level 1 (faster optimal encoder)
        Optimal1 = 5,
        /// optimal parse level 2 (recommended baseline optimal encoder)
        Optimal2 = 6,
        /// optimal parse level 3 (slower optimal encoder)
        Optimal3 = 7,
        /// optimal parse level 4 (very slow optimal encoder)
        Optimal4 = 8,
        /// optimal parse level 5 (don't care about encode speed, maximum compression)
        Optimal5 = 9,

        /// faster than SuperFast, less compression
        HyperFast1 = -1,
        /// faster than HyperFast1, less compression
        HyperFast2 = -2,
        /// faster than HyperFast2, less compression
        HyperFast3 = -3,
        /// fastest, less compression
        HyperFast4 = -4,
    }

    pub type Compress = unsafe extern "system" fn(
        compressor: Compressor,
        rawBuf: *const u8,
        rawLen: usize,
        compBuf: *mut u8,
        level: CompressionLevel,
        pOptions: *const (),
        dictionaryBase: *const (),
        lrm: *const (),
        scratchMem: *mut u8,
        scratchSize: usize,
    ) -> isize;

    pub type Decompress = unsafe extern "system" fn(
        compBuf: *const u8,
        compBufSize: usize,
        rawBuf: *mut u8,
        rawLen: usize,
        fuzzSafe: u32,
        checkCRC: u32,
        verbosity: u32,
        decBufBase: u64,
        decBufSize: usize,
        fpCallback: u64,
        callbackUserData: u64,
        decoderMemory: *mut u8,
        decoderMemorySize: usize,
        threadPhase: u32,
    ) -> isize;

    pub type GetCompressedBufferSizeNeeded =
        unsafe extern "system" fn(compressor: Compressor, rawSize: usize) -> usize;
}

static OODLE_VERSION: &str = "2.9.10";
static OODLE_BASE_URL: &str = "https://github.com/WorkingRobot/OodleUE/raw/refs/heads/main/Engine/Source/Programs/Shared/EpicGames.Oodle/Sdk/";

struct OodlePlatform {
    path: &'static str,
    name: &'static str,
    hash: &'static str,
}

#[cfg(unix)]
static OODLE_PLATFORM: OodlePlatform = OodlePlatform {
    path: "linux/lib",
    name: "liboo2corelinux64.so.9",
    hash: "ed7e98f70be1254a80644efd3ae442ff61f854a2fe9debb0b978b95289884e9c",
};

#[cfg(windows)]
static OODLE_PLATFORM: OodlePlatform = OodlePlatform {
    path: "win/redist",
    name: "oo2core_9_win64.dll",
    hash: "6f5d41a7892ea6b2db420f2458dad2f84a63901c9a93ce9497337b16c195f457",
};

fn url() -> String {
    format!(
        "{OODLE_BASE_URL}/{}/{}/{}",
        OODLE_VERSION, OODLE_PLATFORM.path, OODLE_PLATFORM.name
    )
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("hash mismatch expected: {expected} got {found}")]
    HashMismatch { expected: String, found: String },
    #[error("Oodle compression failed")]
    CompressionFailed,
    #[error("Oodle initialization failed previously")]
    InitializationFailed,
    #[error("IO error {0:?}")]
    Io(#[from] std::io::Error),
    #[error("ureq error {0:?}")]
    Ureq(#[from] ureq::Error),
    #[error("libloading error {0:?}")]
    LibLoading(#[from] libloading::Error),
}

fn check_hash(buffer: &[u8]) -> Result<()> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(buffer);
    let hash = hex::encode(hasher.finalize());
    if hash != OODLE_PLATFORM.hash {
        return Err(Error::HashMismatch {
            expected: OODLE_PLATFORM.hash.into(),
            found: hash,
        });
    }

    Ok(())
}

fn fetch_oodle() -> Result<std::path::PathBuf> {
    let oodle_path = std::env::current_exe()?.with_file_name(OODLE_PLATFORM.name);
    if !oodle_path.exists() {
        let mut buffer = vec![];
        ureq::get(&url())
            .call()?
            .into_reader()
            .read_to_end(&mut buffer)?;
        check_hash(&buffer)?;
        std::fs::write(&oodle_path, buffer)?;
    }
    check_hash(&std::fs::read(&oodle_path)?)?;
    Ok(oodle_path)
}

pub struct Oodle {
    _library: libloading::Library,
    compress: oodle_lz::Compress,
    decompress: oodle_lz::Decompress,
    get_compressed_buffer_size_needed: oodle_lz::GetCompressedBufferSizeNeeded,
}
impl Oodle {
    pub fn compress<S: Write>(
        &self,
        input: &[u8],
        mut output: S,
        compressor: Compressor,
        compression_level: CompressionLevel,
    ) -> Result<usize> {
        unsafe {
            let buffer_size = self.get_compressed_buffer_size_needed(compressor, input.len());
            let mut buffer = vec![0; buffer_size];

            let len = (self.compress)(
                compressor,
                input.as_ptr(),
                input.len(),
                buffer.as_mut_ptr(),
                compression_level,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            );

            if len == -1 {
                return Err(Error::CompressionFailed);
            }
            let len = len as usize;

            output.write_all(&buffer[..len])?;

            Ok(len)
        }
    }
    pub fn decompress(&self, input: &[u8], output: &mut [u8]) -> isize {
        unsafe {
            (self.decompress)(
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                output.len(),
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                0,
                3,
            )
        }
    }
    fn get_compressed_buffer_size_needed(
        &self,
        compressor: oodle_lz::Compressor,
        raw_buffer: usize,
    ) -> usize {
        unsafe { (self.get_compressed_buffer_size_needed)(compressor, raw_buffer) }
    }
}

static OODLE: OnceLock<Option<Oodle>> = OnceLock::new();

fn load_oodle() -> Result<Oodle> {
    let path = fetch_oodle()?;
    unsafe {
        let library = libloading::Library::new(path)?;

        Ok(Oodle {
            compress: *library.get(b"OodleLZ_Compress")?,
            decompress: *library.get(b"OodleLZ_Decompress")?,
            get_compressed_buffer_size_needed: *library
                .get(b"OodleLZ_GetCompressedBufferSizeNeeded")?,
            _library: library,
        })
    }
}

pub fn oodle() -> Result<&'static Oodle> {
    let mut result = None;
    let oodle = OODLE.get_or_init(|| match load_oodle() {
        Err(err) => {
            result = Some(Err(err));
            None
        }
        Ok(oodle) => Some(oodle),
    });
    match (result, oodle) {
        // oodle initialized so return
        (_, Some(oodle)) => Ok(oodle),
        // error during initialization
        (Some(result), _) => result?,
        // no error because initialization was tried and failed before
        _ => Err(Error::InitializationFailed),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_oodle() {
        let oodle = oodle().unwrap();

        let data = b"In tools and when compressing large inputs in one call, consider using
        $OodleXLZ_Compress_AsyncAndWait (in the Oodle2 Ext lib) instead to get parallelism. Alternatively,
        chop the data into small fixed size chunks (we recommend at least 256KiB, i.e. 262144 bytes) and
        call compress on each of them, which decreases compression ratio but makes for trivial parallel
        compression and decompression.";

        let mut buffer = vec![];
        oodle
            .compress(
                data,
                &mut buffer,
                Compressor::Mermaid,
                CompressionLevel::Optimal5,
            )
            .unwrap();

        std::fs::write("comp.bin", &buffer).unwrap();
        dbg!((data.len(), buffer.len()));

        let mut uncomp = vec![0; data.len()];
        oodle.decompress(&buffer, &mut uncomp);

        assert_eq!(data[..], uncomp[..]);
    }
}
