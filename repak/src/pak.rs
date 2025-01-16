use crate::entry::Entry;
use crate::Compression;

use super::ext::{ReadExt, WriteExt};
use super::{Version, VersionMajor};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::collections::BTreeMap;
use std::io::{self, Read, Seek, Write};

#[derive(Debug)]
pub struct PakBuilder {
    key: super::Key,
    oodle: super::Oodle,
    allowed_compression: Vec<Compression>,
    variant: super::PakVariant,
}

impl Default for PakBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PakBuilder {
    pub fn new() -> Self {
        Self {
            key: Default::default(),
            #[cfg(not(feature = "oodle_implicit_dynamic"))]
            oodle: super::Oodle::None,
            #[cfg(feature = "oodle_implicit_dynamic")]
            oodle: super::Oodle::Some(oodle_loader::decompress),
            allowed_compression: Default::default(),
            variant: Default::default(),
        }
    }
    #[cfg(feature = "encryption")]
    pub fn key(mut self, key: aes::Aes256) -> Self {
        self.key = super::Key::Some(key);
        self
    }
    #[cfg(feature = "oodle_explicit")]
    pub fn oodle(mut self, oodle_getter: super::oodle::OodleGetter) -> Self {
        self.oodle = super::Oodle::Some(oodle_getter);
        self
    }
    #[cfg(feature = "compression")]
    pub fn compression(mut self, compression: impl IntoIterator<Item = Compression>) -> Self {
        self.allowed_compression = compression.into_iter().collect();
        self
    }
    pub fn variant(mut self, variant: super::PakVariant) -> Self {
        self.variant = variant;
        self
    }
    pub fn reader<R: Read + Seek>(self, reader: &mut R) -> Result<PakReader, super::Error> {
        PakReader::new_any_inner(reader, self.key, self.oodle, self.variant)
    }
    pub fn reader_with_version<R: Read + Seek>(
        self,
        reader: &mut R,
        version: super::Version,
    ) -> Result<PakReader, super::Error> {
        PakReader::new_inner(reader, version, self.key, self.oodle, self.variant)
    }
    pub fn writer<W: Write + Seek>(
        self,
        writer: W,
        version: super::Version,
        mount_point: String,
        path_hash_seed: Option<u64>,
    ) -> PakWriter<W> {
        PakWriter::new_inner(
            writer,
            self.key,
            version,
            mount_point,
            path_hash_seed,
            self.allowed_compression,
            self.variant,
        )
    }
}

#[derive(Debug)]
pub struct PakReader {
    pak: Pak,
    key: super::Key,
    oodle: super::Oodle,
    variant: super::PakVariant,
}

#[derive(Debug)]
pub struct PakWriter<W: Write + Seek> {
    pak: Pak,
    writer: W,
    key: super::Key,
    allowed_compression: Vec<Compression>,
    variant: super::PakVariant,
}

#[derive(Debug)]
pub(crate) struct Pak {
    version: Version,
    mount_point: String,
    index_offset: Option<u64>,
    index: Index,
    encrypted_index: bool,
    encryption_guid: Option<u128>,
    compression: Vec<Option<Compression>>,
}

impl Pak {
    fn new(version: Version, mount_point: String, path_hash_seed: Option<u64>) -> Self {
        Pak {
            version,
            mount_point,
            index_offset: None,
            index: Index::new(path_hash_seed),
            encrypted_index: false,
            encryption_guid: None,
            compression: (if version.version_major() < VersionMajor::FNameBasedCompression {
                vec![
                    Some(Compression::Zlib),
                    Some(Compression::Gzip),
                    Some(Compression::Oodle),
                ]
            } else {
                vec![]
            }),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Index {
    path_hash_seed: Option<u64>,
    entries: BTreeMap<String, super::entry::Entry>,
}

impl Index {
    fn new(path_hash_seed: Option<u64>) -> Self {
        Index {
            path_hash_seed,
            ..Index::default()
        }
    }

    fn entries(&self) -> &BTreeMap<String, super::entry::Entry> {
        &self.entries
    }

    fn into_entries(self) -> BTreeMap<String, super::entry::Entry> {
        self.entries
    }

    fn add_entry(&mut self, path: &str, entry: super::entry::Entry) {
        self.entries.insert(path.to_string(), entry);
    }
}

#[cfg(feature = "encryption")]
fn decrypt(key: &super::Key, bytes: &mut [u8]) -> Result<(), super::Error> {
    if let super::Key::Some(key) = key {
        use aes::cipher::BlockDecrypt;
        for chunk in bytes.chunks_mut(16) {
            chunk.chunks_mut(4).for_each(|c| c.reverse());
            key.decrypt_block(aes::Block::from_mut_slice(chunk));
            chunk.chunks_mut(4).for_each(|c| c.reverse());
        }
        Ok(())
    } else {
        Err(super::Error::Encrypted)
    }
}

impl PakReader {
    fn new_any_inner<R: Read + Seek>(
        reader: &mut R,
        key: super::Key,
        oodle: super::Oodle,
        variant: super::PakVariant,
    ) -> Result<Self, super::Error> {
        use std::fmt::Write;
        let mut log = "\n".to_owned();

        for ver in Version::iter() {
            match Pak::read(&mut *reader, ver, &key) {
                Ok(pak) => return Ok(Self { pak, key, oodle, variant }),
                Err(err) => writeln!(log, "trying version {} failed: {}", ver, err)?,
            }
        }
        Err(super::Error::UnsupportedOrEncrypted(log))
    }

    fn new_inner<R: Read + Seek>(
        reader: &mut R,
        version: super::Version,
        key: super::Key,
        oodle: super::Oodle,
        variant: super::PakVariant,
    ) -> Result<Self, super::Error> {
        Pak::read(reader, version, &key).map(|pak| Self {
            pak,
            key,
            oodle,
            variant,
        })
    }

    pub fn version(&self) -> super::Version {
        self.pak.version
    }

    pub fn mount_point(&self) -> &str {
        &self.pak.mount_point
    }

    pub fn encrypted_index(&self) -> bool {
        self.pak.encrypted_index
    }

    pub fn encryption_guid(&self) -> Option<u128> {
        self.pak.encryption_guid
    }

    pub fn path_hash_seed(&self) -> Option<u64> {
        self.pak.index.path_hash_seed
    }

    pub fn get<R: Read + Seek>(&self, path: &str, reader: &mut R) -> Result<Vec<u8>, super::Error> {
        let mut data = Vec::new();
        self.read_file(path, reader, &mut data)?;
        Ok(data)
    }

    pub fn read_file<R: Read + Seek, W: Write>(
        &self,
        path: &str,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), super::Error> {
        match self.pak.index.entries().get(path) {
            Some(entry) => {
                let path = format!("{}/{}", self.mount_point(), path);

                let mut last = false;
                let path = path
                    .chars()
                    .filter(|&c| {
                        let keep = c != '/' || !last;
                        last = c == '/';
                        keep
                    })
                    .collect::<String>();
                let path = path.strip_prefix("../../../").unwrap();

                entry.read_file(
                    reader,
                    self.pak.version,
                    &self.pak.compression,
                    &self.key,
                    &self.oodle,
                    writer,
                    path,
                )
            }
            None => Err(super::Error::MissingEntry(path.to_owned())),
        }
    }

    pub fn files(&self) -> Vec<String> {
        self.pak.index.entries().keys().cloned().collect()
    }

    pub fn into_pakwriter<W: Write + Seek>(
        self,
        mut writer: W,
    ) -> Result<PakWriter<W>, super::Error> {
        writer.seek(io::SeekFrom::Start(self.pak.index_offset.unwrap()))?;
        Ok(PakWriter {
            allowed_compression: self.pak.compression.iter().filter_map(|c| *c).collect(),
            pak: self.pak,
            key: self.key,
            writer,
            variant: self.variant,
        })
    }
}

impl<W: Write + Seek> PakWriter<W> {
    fn new_inner(
        writer: W,
        key: super::Key,
        version: Version,
        mount_point: String,
        path_hash_seed: Option<u64>,
        allowed_compression: Vec<Compression>,
        variant: super::PakVariant,
    ) -> Self {
        PakWriter {
            pak: Pak::new(version, mount_point, path_hash_seed),
            writer,
            key,
            allowed_compression,
            variant,
        }
    }

    pub fn into_writer(self) -> W {
        self.writer
    }

    pub fn write_file(&mut self, path: &str, data: impl AsRef<[u8]>) -> Result<(), super::Error> {
        let entry = Entry::write_file(
            &mut self.writer,
            self.pak.version,
            &mut self.pak.compression,
            &self.allowed_compression,
            &self.key,
            self.variant,
            path,
            data,
        )?;
        self.pak.index.add_entry(path, entry);
        Ok(())
    }

    pub fn write_index(mut self) -> Result<W, super::Error> {
        self.pak.write(&mut self.writer, &self.key)?;
        Ok(self.writer)
    }
}

impl Pak {
    fn read<R: Read + Seek>(
        reader: &mut R,
        version: super::Version,
        #[allow(unused)] key: &super::Key,
    ) -> Result<Self, super::Error> {
        // read footer to get index, encryption & compression info
        reader.seek(io::SeekFrom::End(-version.size()))?;
        let footer = super::footer::Footer::read(reader, version)?;
        // read index to get all the entry info
        reader.seek(io::SeekFrom::Start(footer.index_offset))?;
        #[allow(unused_mut)]
        let mut index = reader.read_len(footer.index_size as usize)?;

        // decrypt index if needed
        if footer.encrypted {
            #[cfg(not(feature = "encryption"))]
            return Err(super::Error::Encryption);
            #[cfg(feature = "encryption")]
            decrypt(key, &mut index)?;
        }

        let mut index = io::Cursor::new(index);
        let mount_point = index.read_string()?;
        let len = index.read_u32::<LE>()? as usize;

        let index = if version.version_major() >= VersionMajor::PathHashIndex {
            let path_hash_seed = index.read_u64::<LE>()?;

            // Left in for potential desire to verify path index hashes.
            let _path_hash_index = if index.read_u32::<LE>()? != 0 {
                let path_hash_index_offset = index.read_u64::<LE>()?;
                let path_hash_index_size = index.read_u64::<LE>()?;
                let _path_hash_index_hash = index.read_len(20)?;

                reader.seek(io::SeekFrom::Start(path_hash_index_offset))?;
                let mut path_hash_index_buf = reader.read_len(path_hash_index_size as usize)?;
                // TODO verify hash

                if footer.encrypted {
                    #[cfg(not(feature = "encryption"))]
                    return Err(super::Error::Encryption);
                    #[cfg(feature = "encryption")]
                    decrypt(key, &mut path_hash_index_buf)?;
                }

                let mut path_hash_index = vec![];
                let mut phi_reader = io::Cursor::new(&mut path_hash_index_buf);
                for _ in 0..phi_reader.read_u32::<LE>()? {
                    let hash = phi_reader.read_u64::<LE>()?;
                    let encoded_entry_offset = phi_reader.read_u32::<LE>()?;
                    path_hash_index.push((hash, encoded_entry_offset));
                }

                Some(path_hash_index)
            } else {
                None
            };

            // Left in for potential desire to verify full directory index hashes.
            let full_directory_index = if index.read_u32::<LE>()? != 0 {
                let full_directory_index_offset = index.read_u64::<LE>()?;
                let full_directory_index_size = index.read_u64::<LE>()?;
                let _full_directory_index_hash = index.read_len(20)?;

                reader.seek(io::SeekFrom::Start(full_directory_index_offset))?;
                #[allow(unused_mut)]
                let mut full_directory_index =
                    reader.read_len(full_directory_index_size as usize)?;
                // TODO verify hash

                if footer.encrypted {
                    #[cfg(not(feature = "encryption"))]
                    return Err(super::Error::Encryption);
                    #[cfg(feature = "encryption")]
                    decrypt(key, &mut full_directory_index)?;
                }
                let mut fdi = io::Cursor::new(full_directory_index);

                let dir_count = fdi.read_u32::<LE>()? as usize;
                let mut directories = BTreeMap::new();
                for _ in 0..dir_count {
                    let dir_name = fdi.read_string()?;
                    let file_count = fdi.read_u32::<LE>()? as usize;
                    let mut files = BTreeMap::new();
                    for _ in 0..file_count {
                        let file_name = fdi.read_string()?;
                        files.insert(file_name, fdi.read_u32::<LE>()?);
                    }
                    directories.insert(dir_name, files);
                }
                Some(directories)
            } else {
                None
            };
            let size = index.read_u32::<LE>()? as usize;
            let encoded_entries = index.read_len(size)?;

            let mut entries_by_path = BTreeMap::new();
            if let Some(fdi) = &full_directory_index {
                let mut encoded_entries = io::Cursor::new(&encoded_entries);
                for (dir_name, dir) in fdi {
                    for (file_name, encoded_offset) in dir {
                        if *encoded_offset == 0x80000000 {
                            println!("{file_name:?} has invalid offset: 0x{encoded_offset:08x}");
                            continue;
                        }
                        encoded_entries.seek(io::SeekFrom::Start(*encoded_offset as u64))?;
                        let entry =
                            super::entry::Entry::read_encoded(&mut encoded_entries, version)?;
                        let path = format!(
                            "{}{}",
                            dir_name.strip_prefix('/').unwrap_or(dir_name),
                            file_name
                        );
                        entries_by_path.insert(path, entry);
                    }
                }
            }

            assert_eq!(index.read_u32::<LE>()?, 0, "remaining index bytes are 0"); // TODO possibly remaining unencoded entries?

            Index {
                path_hash_seed: Some(path_hash_seed),
                entries: entries_by_path,
            }
        } else {
            let mut entries = BTreeMap::new();
            for _ in 0..len {
                entries.insert(
                    index.read_string()?,
                    super::entry::Entry::read(&mut index, version)?,
                );
            }
            Index {
                path_hash_seed: None,
                entries,
            }
        };

        Ok(Pak {
            version,
            mount_point,
            index_offset: Some(footer.index_offset),
            index,
            encrypted_index: footer.encrypted,
            encryption_guid: footer.encryption_uuid,
            compression: footer.compression,
        })
    }

    fn write<W: Write + Seek>(
        &self,
        writer: &mut W,
        key: &super::Key,
    ) -> Result<(), super::Error> {
        let index_offset = writer.stream_position()?;
        let mut index_buf = vec![];
        let mut index_writer = io::Cursor::new(&mut index_buf);
        index_writer.write_string(&self.mount_point)?;

        let secondary_index = if self.version < super::Version::V10 {
            let record_count = self.index.entries.len() as u32;
            index_writer.write_u32::<LE>(record_count)?;
            for (path, entry) in &self.index.entries {
                index_writer.write_string(path)?;
                entry.write(
                    &mut index_writer,
                    self.version,
                    super::entry::EntryLocation::Index,
                )?;
            }
            None
        } else {
            let record_count = self.index.entries.len() as u32;
            let path_hash_seed = self.index.path_hash_seed.unwrap_or_default();
            index_writer.write_u32::<LE>(record_count)?;
            index_writer.write_u64::<LE>(path_hash_seed)?;

            let (encoded_entries, offsets) = {
                let mut offsets = Vec::with_capacity(self.index.entries.len());
                let mut encoded_entries = io::Cursor::new(vec![]);
                for entry in self.index.entries.values() {
                    offsets.push(encoded_entries.get_ref().len() as u32);
                    entry.write_encoded(&mut encoded_entries)?;
                }
                (encoded_entries.into_inner(), offsets)
            };

            // The index is organized sequentially as:
            // - Index Header, which contains:
            //     - Mount Point (u32 len + string w/ terminating byte)
            //     - Entry Count (u32)
            //     - Path Hash Seed (u64)
            //     - Has Path Hash Index (u32); if true, then:
            //         - Path Hash Index Offset (u64)
            //         - Path Hash Index Size (u64)
            //         - Path Hash Index Hash ([u8; 20])
            //     - Has Full Directory Index (u32); if true, then:
            //         - Full Directory Index Offset (u64)
            //         - Full Directory Index Size (u64)
            //         - Full Directory Index Hash ([u8; 20])
            //     - Encoded Index Records Size
            //     - (Unused) File Count
            // - Path Hash Index
            // - Full Directory Index
            // - Encoded Index Records; each encoded index record is (0xC bytes) from:
            //     - Flags (u32)
            //     - Offset (u32)
            //     - Size (u32)
            let bytes_before_phi = {
                let mut size = 0;
                size += 4; // mount point len
                size += self.mount_point.len() as u64 + 1; // mount point string w/ NUL byte
                size += 8; // path hash seed
                size += 4; // record count
                size += 4; // has path hash index (since we're generating, always true)
                size += 8 + 8 + 20; // path hash index offset, size and hash
                size += 4; // has full directory index (since we're generating, always true)
                size += 8 + 8 + 20; // full directory index offset, size and hash
                size += 4; // encoded entry size
                size += encoded_entries.len() as u64;
                size += 4; // unused file count
                size
            };

            let path_hash_index_offset = index_offset + bytes_before_phi;

            let mut phi_buf = vec![];
            let mut phi_writer = io::Cursor::new(&mut phi_buf);
            generate_path_hash_index(
                &mut phi_writer,
                path_hash_seed,
                &self.index.entries,
                &offsets,
            )?;

            let full_directory_index_offset = path_hash_index_offset + phi_buf.len() as u64;

            let mut fdi_buf = vec![];
            let mut fdi_writer = io::Cursor::new(&mut fdi_buf);
            generate_full_directory_index(&mut fdi_writer, &self.index.entries, &offsets)?;

            index_writer.write_u32::<LE>(1)?; // we have path hash index
            index_writer.write_u64::<LE>(path_hash_index_offset)?;
            index_writer.write_u64::<LE>(phi_buf.len() as u64)?; // path hash index size
            index_writer.write_all(&hash(&phi_buf))?;

            index_writer.write_u32::<LE>(1)?; // we have full directory index
            index_writer.write_u64::<LE>(full_directory_index_offset)?;
            index_writer.write_u64::<LE>(fdi_buf.len() as u64)?; // path hash index size
            index_writer.write_all(&hash(&fdi_buf))?;

            index_writer.write_u32::<LE>(encoded_entries.len() as u32)?;
            index_writer.write_all(&encoded_entries)?;

            index_writer.write_u32::<LE>(0)?;

            Some((phi_buf, fdi_buf))
        };

        let index_hash = hash(&index_buf);

        writer.write_all(&index_buf)?;

        if let Some((phi_buf, fdi_buf)) = secondary_index {
            writer.write_all(&phi_buf[..])?;
            writer.write_all(&fdi_buf[..])?;
        }

        let footer = super::footer::Footer {
            encryption_uuid: match key {
                super::Key::Some(_) => Some(0x205C5A7D_u128), // Standard UE4 encryption GUID
                super::Key::None => None,
            },
            encrypted: false, // Keep false since we're not encrypting the index yet
            magic: super::MAGIC,
            version: self.version,
            version_major: self.version.version_major(),
            index_offset,
            index_size: index_buf.len() as u64,
            hash: index_hash,
            frozen: false,
            compression: self.compression.clone(),
        };

        footer.write(writer)?;
        Ok(())
    }
}

fn hash(data: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn generate_path_hash_index<W: Write>(
    writer: &mut W,
    path_hash_seed: u64,
    entries: &BTreeMap<String, super::entry::Entry>,
    offsets: &Vec<u32>,
) -> Result<(), super::Error> {
    writer.write_u32::<LE>(entries.len() as u32)?;
    for (path, offset) in entries.keys().zip(offsets) {
        let path_hash = fnv64_path(path, path_hash_seed);
        writer.write_u64::<LE>(path_hash)?;
        writer.write_u32::<LE>(*offset)?;
    }

    writer.write_u32::<LE>(0)?;

    Ok(())
}

fn fnv64<I>(data: I, offset: u64) -> u64
where
    I: IntoIterator<Item = u8>,
{
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001b3;
    let mut hash = OFFSET.wrapping_add(offset);
    for b in data.into_iter() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn fnv64_path(path: &str, offset: u64) -> u64 {
    let lower = path.to_lowercase();
    let data = lower.encode_utf16().flat_map(u16::to_le_bytes);
    fnv64(data, offset)
}

fn split_path_child(path: &str) -> Option<(&str, &str)> {
    if path == "/" || path.is_empty() {
        None
    } else {
        let path = path.strip_suffix('/').unwrap_or(path);
        let i = path.rfind('/').map(|i| i + 1);
        match i {
            Some(i) => Some(path.split_at(i)),
            None => Some(("/", path)),
        }
    }
}

fn generate_full_directory_index<W: Write>(
    writer: &mut W,
    entries: &BTreeMap<String, super::entry::Entry>,
    offsets: &Vec<u32>,
) -> Result<(), super::Error> {
    let mut fdi: BTreeMap<&str, BTreeMap<&str, u32>> = Default::default();
    for (path, offset) in entries.keys().zip(offsets) {
        let mut p = path.as_str();
        while let Some((parent, _)) = split_path_child(p) {
            p = parent;
            fdi.entry(p).or_default();
        }

        let (directory, filename) = split_path_child(path).expect("none root path");

        fdi.entry(directory).or_default().insert(filename, *offset);
    }

    writer.write_u32::<LE>(fdi.len() as u32)?;
    for (directory, files) in &fdi {
        writer.write_string(directory)?;
        writer.write_u32::<LE>(files.len() as u32)?;
        for (filename, offset) in files {
            writer.write_string(filename)?;
            writer.write_u32::<LE>(*offset)?;
        }
    }

    Ok(())
}

#[cfg(feature = "encryption")]
fn encrypt(key: aes::Aes256, bytes: &mut [u8]) {
    use aes::cipher::BlockEncrypt;
    for chunk in bytes.chunks_mut(16) {
        chunk.chunks_mut(4).for_each(|c| c.reverse());
        key.encrypt_block(aes::Block::from_mut_slice(chunk));
        chunk.chunks_mut(4).for_each(|c| c.reverse());
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_split_path_child() {
        assert_eq!(
            split_path_child("a/really/long/path"),
            Some(("a/really/long/", "path"))
        );
        assert_eq!(
            split_path_child("a/really/long/"),
            Some(("a/really/", "long"))
        );
        assert_eq!(split_path_child("a"), Some(("/", "a")));
        assert_eq!(split_path_child("a//b"), Some(("a//", "b")));
        assert_eq!(split_path_child("a//"), Some(("a/", "")));
        assert_eq!(split_path_child("/"), None);
        assert_eq!(split_path_child(""), None);
    }
}
