use anyhow::{anyhow, Context, Result};

use std::sync::OnceLock;

type OodleDecompress = fn(comp_buf: &[u8], raw_buf: &mut [u8]) -> i32;

#[allow(non_camel_case_types)]
type OodleLZ_Decompress = unsafe extern "win64" fn(
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
) -> i32;

pub fn decompress() -> Result<OodleDecompress, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    return Ok(windows_oodle::decompress_wrapper_windows);
    #[cfg(unix)]
    return Ok(linux_oodle::oodle_loader_linux());
}

fn call_decompress(comp_buf: &[u8], raw_buf: &mut [u8], decompress: OodleLZ_Decompress) -> i32 {
    unsafe {
        decompress(
            comp_buf.as_ptr(),
            comp_buf.len(),
            raw_buf.as_mut_ptr(),
            raw_buf.len(),
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

static OODLE_HASH: [u8; 20] = hex_literal::hex!("4bcc73614cb8fd2b0bce8d0f91ee5f3202d9d624");
static OODLE_DLL_NAME: &str = "oo2core_9_win64.dll";

fn fetch_oodle() -> Result<std::path::PathBuf> {
    use sha1::{Digest, Sha1};

    let oodle_path = std::env::current_exe()?.with_file_name(OODLE_DLL_NAME);

    if !oodle_path.exists() {
        let mut compressed = vec![];
        ureq::get("https://origin.warframe.com/origin/50F7040A/index.txt.lzma")
            .call()?
            .into_reader()
            .read_to_end(&mut compressed)?;

        let mut decompressed = vec![];
        lzma_rs::lzma_decompress(&mut std::io::Cursor::new(compressed), &mut decompressed).unwrap();
        let index = String::from_utf8(decompressed)?;
        let line = index
            .lines()
            .find(|l| l.contains(OODLE_DLL_NAME))
            .with_context(|| format!("{OODLE_DLL_NAME} not found in index"))?;
        let path = line.split_once(',').context("failed to parse index")?.0;

        let mut compressed = vec![];
        ureq::get(&format!("https://content.warframe.com{path}"))
            .call()?
            .into_reader()
            .read_to_end(&mut compressed)?;

        let mut decompressed = vec![];
        lzma_rs::lzma_decompress(&mut std::io::Cursor::new(compressed), &mut decompressed).unwrap();

        std::fs::write(&oodle_path, decompressed)?;
    }

    let mut hasher = Sha1::new();
    hasher.update(std::fs::read(&oodle_path)?);
    let hash = hasher.finalize();
    (hash[..] == OODLE_HASH).then_some(()).ok_or_else(|| {
        anyhow!(
            "oodle hash mismatch expected: {} got: {} ",
            hex::encode(OODLE_HASH),
            hex::encode(hash)
        )
    })?;

    Ok(oodle_path)
}

#[cfg(windows)]
mod windows_oodle {
    use super::*;

    static DECOMPRESS: OnceLock<(OodleLZ_Decompress, libloading::Library)> = OnceLock::new();

    pub fn decompress_wrapper_windows(comp_buf: &[u8], raw_buf: &mut [u8]) -> i32 {
        let decompress = DECOMPRESS.get_or_init(|| {
            let path = fetch_oodle().context("failed to fetch oodle").unwrap();

            let lib = unsafe { libloading::Library::new(path) }
                .context("failed to load oodle")
                .unwrap();

            (*unsafe { lib.get(b"OodleLZ_Decompress") }.unwrap(), lib)
        });
        call_decompress(comp_buf, raw_buf, decompress.0)
    }
}

#[cfg(unix)]
mod linux_oodle {
    use super::*;

    use object::pe::{
        ImageNtHeaders64, IMAGE_REL_BASED_DIR64, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_WRITE,
    };
    use object::read::pe::{ImageOptionalHeader, ImageThunkData, PeFile64};

    use object::{LittleEndian as LE, Object, ObjectSection};
    use std::collections::HashMap;
    use std::ffi::{c_void, CStr};

    #[repr(C)]
    struct ThreadInformationBlock {
        exception_list: *const c_void,
        stack_base: *const c_void,
        stack_limit: *const c_void,
        sub_system_tib: *const c_void,
        fiber_data: *const c_void,
        arbitrary_user_pointer: *const c_void,
        teb: *const c_void,
    }

    const TIB: ThreadInformationBlock = ThreadInformationBlock {
        exception_list: std::ptr::null(),
        stack_base: std::ptr::null(),
        stack_limit: std::ptr::null(),
        sub_system_tib: std::ptr::null(),
        fiber_data: std::ptr::null(),
        arbitrary_user_pointer: std::ptr::null(),
        teb: std::ptr::null(),
    };

    static DECOMPRESS: OnceLock<OodleLZ_Decompress> = OnceLock::new();

    fn decompress_wrapper(comp_buf: &[u8], raw_buf: &mut [u8]) -> i32 {
        unsafe {
            // Set GS register in calling thread
            const ARCH_SET_GS: i32 = 0x1001;
            libc::syscall(libc::SYS_arch_prctl, ARCH_SET_GS, &TIB);

            // Call actual decompress function
            call_decompress(comp_buf, raw_buf, *DECOMPRESS.get().unwrap())
        }
    }

    #[allow(non_snake_case)]
    mod imports {
        use super::*;

        pub unsafe extern "win64" fn OutputDebugStringA(string: *const std::ffi::c_char) {
            print!("[OODLE] {}", CStr::from_ptr(string).to_string_lossy());
        }
        pub unsafe extern "win64" fn GetProcessHeap() -> *const c_void {
            0x12345678 as *const c_void
        }
        pub unsafe extern "win64" fn HeapAlloc(
            _heap: *const c_void,
            flags: i32,
            size: usize,
        ) -> *const c_void {
            assert_eq!(0, flags);
            libc::malloc(size)
        }
        pub unsafe extern "win64" fn HeapFree(
            _heap: *const c_void,
            _flags: i32,
            ptr: *mut c_void,
        ) -> bool {
            libc::free(ptr);
            true
        }
        pub unsafe extern "win64" fn memset(
            ptr: *mut c_void,
            value: i32,
            num: usize,
        ) -> *const c_void {
            libc::memset(ptr, value, num)
        }
        pub unsafe extern "win64" fn memmove(
            destination: *mut c_void,
            source: *const c_void,
            num: usize,
        ) -> *const c_void {
            libc::memmove(destination, source, num)
        }
        pub unsafe extern "win64" fn memcpy(
            destination: *mut c_void,
            source: *const c_void,
            num: usize,
        ) -> *const c_void {
            libc::memcpy(destination, source, num)
        }
    }

    // Create some unique function pointers to use for unimplemented imports
    const DEBUG_FNS: [*const fn(); 100] = gen_debug_fns();
    static mut DEBUG_NAMES: [&str; 100] = [""; 100];
    const fn gen_debug_fns() -> [*const fn(); 100] {
        fn log<const I: usize>() {
            unimplemented!("import {:?}", unsafe { DEBUG_NAMES[I] });
        }
        let mut array = [std::ptr::null(); 100];
        seq_macro::seq!(N in 0..100 {
            array[N] = log::<N> as *const fn();
        });
        array
    }

    pub fn oodle_loader_linux() -> OodleDecompress {
        DECOMPRESS.get_or_init(|| get_decompress_inner().unwrap());
        decompress_wrapper
    }

    fn get_decompress_inner() -> Result<OodleLZ_Decompress> {
        fetch_oodle()?;
        let oodle = std::env::current_exe()
            .unwrap()
            .with_file_name(OODLE_DLL_NAME);
        let dll = std::fs::read(oodle)?;

        let obj_file = PeFile64::parse(&*dll)?;

        let size = obj_file.nt_headers().optional_header.size_of_image() as usize;
        let header_size = obj_file.nt_headers().optional_header.size_of_headers() as usize;

        let image_base = obj_file.relative_address_base() as usize;

        // Create map
        let mmap = unsafe {
            std::slice::from_raw_parts_mut(
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                ) as *mut u8,
                size,
            )
        };

        let map_base = mmap.as_ptr();

        // Copy header to map
        mmap[0..header_size].copy_from_slice(&dll[0..header_size]);
        unsafe {
            assert_eq!(
                0,
                libc::mprotect(
                    mmap.as_mut_ptr() as *mut c_void,
                    header_size,
                    libc::PROT_READ
                )
            );
        }

        // Copy section data to map
        for section in obj_file.sections() {
            let address = section.address() as usize;
            let data = section.data()?;
            mmap[(address - image_base)..(address - image_base + data.len())]
                .copy_from_slice(section.data()?);
        }

        // Apply relocations
        let sections = obj_file.section_table();
        let mut blocks = obj_file
            .data_directories()
            .relocation_blocks(&*dll, &sections)?
            .unwrap();

        while let Some(block) = blocks.next()? {
            let block_address = block.virtual_address();
            let block_data = sections.pe_data_at(&*dll, block_address).map(object::Bytes);
            for reloc in block {
                let offset = (reloc.virtual_address - block_address) as usize;
                match reloc.typ {
                    IMAGE_REL_BASED_DIR64 => {
                        let addend = block_data
                            .and_then(|data| data.read_at::<object::U64Bytes<LE>>(offset).ok())
                            .map(|addend| addend.get(LE));
                        if let Some(addend) = addend {
                            mmap[reloc.virtual_address as usize
                                ..reloc.virtual_address as usize + 8]
                                .copy_from_slice(&u64::to_le_bytes(
                                    addend - image_base as u64 + map_base as u64,
                                ));
                        }
                    }
                    _ => unimplemented!(),
                }
            }
        }

        // Fix up imports
        let import_table = obj_file.import_table()?.unwrap();
        let mut import_descs = import_table.descriptors()?;

        let mut i = 0;
        while let Some(import_desc) = import_descs.next()? {
            let mut thunks = import_table.thunks(import_desc.original_first_thunk.get(LE))?;

            let mut address = import_desc.first_thunk.get(LE) as usize;
            while let Some(thunk) = thunks.next::<ImageNtHeaders64>()? {
                let (_hint, name) = import_table.hint_name(thunk.address())?;
                let name = String::from_utf8_lossy(name).to_string();

                use imports::*;

                let fn_addr = match name.as_str() {
                    "OutputDebugStringA" => OutputDebugStringA as usize,
                    "GetProcessHeap" => GetProcessHeap as usize,
                    "HeapAlloc" => HeapAlloc as usize,
                    "HeapFree" => HeapFree as usize,
                    "memset" => memset as usize,
                    "memcpy" => memcpy as usize,
                    "memmove" => memmove as usize,
                    _ => {
                        unsafe { DEBUG_NAMES[i] = name.leak() }
                        let a = DEBUG_FNS[i] as usize;
                        i += 1;
                        a
                    }
                };

                mmap[address..address + 8].copy_from_slice(&usize::to_le_bytes(fn_addr));

                address += 8;
            }
        }

        // Build export table
        let mut exports = HashMap::new();
        for export in obj_file.exports()? {
            let name = String::from_utf8_lossy(export.name());
            let address = export.address() - image_base as u64 + map_base as u64;
            exports.insert(name, address as *const c_void);
        }

        // Fix section permissions
        for section in obj_file.sections() {
            let address = section.address() as usize;
            let data = section.data()?;
            let size = data.len();

            let mut permissions = 0;

            let flags = match section.flags() {
                object::SectionFlags::Coff { characteristics } => characteristics,
                _ => unreachable!(),
            };

            if 0 != flags & IMAGE_SCN_MEM_READ {
                permissions |= libc::PROT_READ;
            }
            if 0 != flags & IMAGE_SCN_MEM_WRITE {
                permissions |= libc::PROT_WRITE;
            }
            if 0 != flags & IMAGE_SCN_MEM_EXECUTE {
                permissions |= libc::PROT_EXEC;
            }

            unsafe {
                assert_eq!(
                    0,
                    libc::mprotect(
                        mmap.as_mut_ptr().add(address - image_base) as *mut c_void,
                        size,
                        permissions
                    )
                );
            }
        }

        // Break things!
        Ok(unsafe { std::mem::transmute(exports["OodleLZ_Decompress"]) })
    }
}
