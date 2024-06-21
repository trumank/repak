mod alloc;

use repak::PakBuilder;
use repak::PakReader;
use repak::PakWriter;
use std::ffi::CString;
use std::io::Read;
use std::io::SeekFrom;

use std::ffi::CStr;
use std::io::{Seek, Write};
use std::os::raw::{c_char, c_void};

#[repr(C)]
pub struct StreamCallbacks {
    context: *mut c_void,
    read: extern "C" fn(*mut c_void, *mut u8, usize) -> isize,
    write: extern "C" fn(*mut c_void, *const u8, usize) -> isize,
    seek: extern "C" fn(*mut c_void, i64, i32) -> i64,
    flush: extern "C" fn(*mut c_void) -> i32,
}

pub struct Stream {
    callbacks: StreamCallbacks,
}

impl Stream {
    pub fn new(callbacks: StreamCallbacks) -> Self {
        Stream { callbacks }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let result = (self.callbacks.read)(self.callbacks.context, buf.as_mut_ptr(), buf.len());
        if result < 0 {
            Err(std::io::Error::from_raw_os_error(result as i32))
        } else {
            Ok(result as usize)
        }
    }
}
impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let result = (self.callbacks.write)(self.callbacks.context, buf.as_ptr(), buf.len());
        if result < 0 {
            Err(std::io::Error::from_raw_os_error(result as i32))
        } else {
            Ok(result as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let result = (self.callbacks.flush)(self.callbacks.context);
        if result < 0 {
            Err(std::io::Error::from_raw_os_error(result))
        } else {
            Ok(())
        }
    }
}

impl Seek for Stream {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let (offset, whence) = match pos {
            SeekFrom::Start(offset) => (offset as i64, 0),
            SeekFrom::End(offset) => (offset, 2),
            SeekFrom::Current(offset) => (offset, 1),
        };
        let result = (self.callbacks.seek)(self.callbacks.context, offset, whence);
        if result < 0 {
            Err(std::io::Error::from_raw_os_error(result as i32))
        } else {
            Ok(result as u64)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pak_builder_new() -> *mut PakBuilder {
    let builder = PakBuilder::new();
    Box::into_raw(Box::new(builder))
}

#[no_mangle]
pub unsafe extern "C" fn pak_builder_drop(builder: *mut PakBuilder) {
    drop(Box::from_raw(builder))
}

#[no_mangle]
pub unsafe extern "C" fn pak_reader_drop(reader: *mut PakReader) {
    drop(Box::from_raw(reader))
}

#[no_mangle]
pub unsafe extern "C" fn pak_writer_drop(writer: *mut PakWriter<Stream>) {
    drop(Box::from_raw(writer))
}

#[no_mangle]
pub unsafe extern "C" fn pak_buffer_drop(buf: *mut u8, len: usize) {
    drop(Box::from_raw(std::slice::from_raw_parts_mut(buf, len)));
}

#[no_mangle]
pub extern "C" fn pak_builder_key(builder: *mut PakBuilder, key: &[u8; 32]) -> *mut PakBuilder {
    use repak::encryption::KeyInit;
    let builder = unsafe { Box::from_raw(builder) }
        .key(repak::encryption::Aes256::new_from_slice(key).unwrap());
    println!("key = {key:X?}");
    Box::into_raw(Box::new(builder))
}

//#[no_mangle]
//pub extern "C" fn pak_builder_compression(builder: *mut PakBuilder, compressions: *const Compression, count: usize) -> *mut PakBuilder {
//    let compressions = unsafe { std::slice::from_raw_parts(compressions, count) };
//    let builder = unsafe { Box::from_raw(builder) }.compression(compressions.to_vec());
//    Box::into_raw(Box::new(builder))
//}

#[no_mangle]
pub unsafe extern "C" fn pak_builder_reader(
    builder: *mut PakBuilder,
    ctx: StreamCallbacks,
) -> *mut PakReader {
    let mut stream = Stream::new(ctx);
    match Box::from_raw(builder).reader(&mut stream) {
        Ok(reader) => Box::into_raw(Box::new(reader)),
        Err(e) => {println!("{e}");std::ptr::null_mut()},
    }
}

//#[no_mangle]
//pub extern "C" fn pak_builder_reader_with_version(builder: *mut PakBuilder, reader_ctx: *mut ReaderContext, version: Version) -> *mut PakReader {
//    let reader_ctx = unsafe { &*reader_ctx };
//    let reader = ReaderWithCallback {
//        context: reader_ctx.reader,
//        read_callback: reader_ctx.read_cb,
//        seek_callback: reader_ctx.seek_cb,
//    };
//    let reader = unsafe { Box::from_raw(builder) }.reader_with_version(&mut reader, version).unwrap();
//    Box::into_raw(Box::new(reader))
//}

#[no_mangle]
pub unsafe extern "C" fn pak_builder_writer(
    builder: *mut PakBuilder,
    ctx: StreamCallbacks,
    version: repak::Version,
    mount_point: *const c_char,
    path_hash_seed: u64,
) -> *mut PakWriter<Stream> {
    let mount_point = CStr::from_ptr(mount_point).to_str().unwrap();
    let stream = Stream::new(ctx);
    let writer = Box::from_raw(builder).writer(
        stream,
        version,
        mount_point.to_string(),
        Some(path_hash_seed),
    );
    Box::into_raw(Box::new(writer))
}

#[no_mangle]
pub extern "C" fn pak_reader_get(
    reader: &PakReader,
    path: *const c_char,
    ctx: StreamCallbacks,
    buffer: &mut *mut u8,
    length: &mut usize,
) -> i32 {
    let path = unsafe { CStr::from_ptr(path) }.to_str().unwrap();
    match reader.get(path, &mut Stream::new(ctx)) {
        Ok(data) => {
            let buf = data.into_boxed_slice();
            let len = buf.len();
            *buffer = Box::into_raw(buf) as *mut u8;
            *length = len;
            0
        }
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "C" fn pak_reader_files(reader: &PakReader, len: &mut usize) -> *mut *mut c_char {
    let c_files: Vec<*mut c_char> = reader
        .files()
        .into_iter()
        .map(|file| CString::new(file).unwrap().into_raw())
        .collect();
    let buf: Box<[*mut c_char]> = c_files.into_boxed_slice();
    *len = buf.len();
    Box::into_raw(buf) as *mut *mut c_char
}
#[no_mangle]
pub unsafe extern "C" fn pak_drop_files(buf: *mut *mut c_char, len: usize) {
    let boxed_slice: Box<[*mut c_char]> = Box::from_raw(std::slice::from_raw_parts_mut(buf, len));

    for i in 0..len {
        if !boxed_slice[i].is_null() {
            drop(CString::from_raw(boxed_slice[i]));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pak_writer_write_file(
    writer: *mut PakWriter<Stream>,
    path: *const c_char,
    data: *const u8,
    data_len: usize,
) -> i32 {
    let path = unsafe { CStr::from_ptr(path) }.to_str().unwrap();
    let data = unsafe { std::slice::from_raw_parts(data, data_len) };
    match unsafe { &mut *writer }.write_file(path, data) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn pak_writer_write_index(writer: *mut PakWriter<Stream>) -> i32 {
    match unsafe { Box::from_raw(writer) }.write_index() {
        Ok(_) => 0,
        Err(_) => 1,
    }
}
