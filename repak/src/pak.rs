use super::ext::{ReadExt, WriteExt};
use super::{Version, VersionMajor};
use aes::Aes256;
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::collections::BTreeMap;
use std::io::{self, Read, Seek, Write};

#[derive(Debug)]
pub struct PakReader {
    pak: Pak,
    key: Option<aes::Aes256>,
}

#[derive(Debug)]
pub struct PakWriter<W: Write + Seek> {
    pak: Pak,
    writer: W,
    key: Option<aes::Aes256>,
}

#[derive(Debug)]
pub struct Pak {
    version: Version,
    mount_point: String,
    index: Index,
}

impl Pak {
    fn new(version: Version, mount_point: String, path_hash_seed: Option<u64>) -> Self {
        Pak {
            version,
            mount_point,
            index: Index::new(path_hash_seed),
        }
    }
}

#[derive(Debug, Default)]
pub struct Index {
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

fn decrypt(key: &Option<aes::Aes256>, bytes: &mut [u8]) -> Result<(), super::Error> {
    if let Some(key) = &key {
        use aes::cipher::BlockDecrypt;
        for chunk in bytes.chunks_mut(16) {
            key.decrypt_block(aes::Block::from_mut_slice(chunk))
        }
        Ok(())
    } else {
        Err(super::Error::Encrypted)
    }
}

impl PakReader {
    pub fn new_any<R: Read + Seek>(
        mut reader: R,
        key: Option<aes::Aes256>,
    ) -> Result<Self, super::Error> {
        for ver in Version::iter() {
            match Pak::read(&mut reader, ver, key.clone()) {
                Ok(pak) => {
                    return Ok(PakReader { pak, key });
                }
                _ => continue,
            }
        }
        Err(super::Error::Other("version unsupported"))
    }

    pub fn version(&self) -> super::Version {
        self.pak.version
    }

    pub fn mount_point(&self) -> &str {
        &self.pak.mount_point
    }

    pub fn get<R: Read + Seek>(&self, path: &str, reader: &mut R) -> Result<Vec<u8>, super::Error> {
        let mut data = Vec::new();
        self.read_file(path, reader, &mut data)?;
        Ok(data)
    }

    pub fn read_file<R: Read + Seek, W: io::Write>(
        &self,
        path: &str,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), super::Error> {
        match self.pak.index.entries().get(path) {
            Some(entry) => entry.read_file(reader, self.pak.version, self.key.as_ref(), writer),
            None => Err(super::Error::Other("no file found at given path")),
        }
    }

    pub fn files(&self) -> Vec<String> {
        self.pak.index.entries().keys().cloned().collect()
    }
}

impl<W: Write + io::Seek> PakWriter<W> {
    pub fn new(
        writer: W,
        key: Option<aes::Aes256>,
        version: Version,
        mount_point: String,
        path_hash_seed: Option<u64>,
    ) -> Self {
        PakWriter {
            pak: Pak::new(version, mount_point, path_hash_seed),
            writer,
            key,
        }
    }

    pub fn into_writer(self) -> W {
        self.writer
    }

    pub fn write_file<R: Read>(&mut self, path: &str, reader: &mut R) -> Result<(), super::Error> {
        let mut data = vec![];
        reader.read_to_end(&mut data)?;

        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(&data);

        let offset = self.writer.stream_position()?;
        let len = data.len() as u64;

        let entry = super::entry::Entry {
            offset,
            compressed: len,
            uncompressed: len,
            compression: super::Compression::None,
            timestamp: None,
            hash: Some(hasher.finalize().into()),
            blocks: None,
            encrypted: false,
            block_uncompressed: None,
        };

        entry.write(
            &mut self.writer,
            self.pak.version,
            super::entry::EntryLocation::Data,
        )?;

        self.pak.index.add_entry(path, entry);

        self.writer.write_all(&data)?;
        Ok(())
    }

    pub fn write_index(mut self) -> Result<W, super::Error> {
        self.pak.write(&mut self.writer, self.key)?;
        Ok(self.writer)
    }
}

impl Pak {
    fn read<R: Read + Seek>(
        mut reader: R,
        version: super::Version,
        key: Option<aes::Aes256>,
    ) -> Result<Self, super::Error> {
        // read footer to get index, encryption & compression info
        reader.seek(io::SeekFrom::End(-version.size()))?;
        let footer = super::footer::Footer::read(&mut reader, version)?;
        // read index to get all the entry info
        reader.seek(io::SeekFrom::Start(footer.index_offset))?;
        let mut index = reader.read_len(footer.index_size as usize)?;

        // decrypt index if needed
        if footer.encrypted {
            decrypt(&key, &mut index)?;
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
                    decrypt(&key, &mut path_hash_index_buf)?;
                }

                let mut path_hash_index = vec![];
                let mut phi_reader = io::Cursor::new(&mut path_hash_index_buf);
                for _ in 0..len {
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
                let mut full_directory_index =
                    reader.read_len(full_directory_index_size as usize)?;
                // TODO verify hash

                if footer.encrypted {
                    decrypt(&key, &mut full_directory_index)?;
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
            index,
        })
    }

    fn write<W: Write + Seek>(
        &self,
        writer: &mut W,
        _key: Option<aes::Aes256>,
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
                size += self.index.entries.len() as u64 * {
                    4 // flags
                        + 4 // offset
                        + 4 // size
                };
                size += 4; // unused file count
                size
            };

            let path_hash_index_offset = index_offset + bytes_before_phi;

            let mut phi_buf = vec![];
            let mut phi_writer = io::Cursor::new(&mut phi_buf);
            generate_path_hash_index(&mut phi_writer, path_hash_seed, &self.index.entries)?;

            let full_directory_index_offset = path_hash_index_offset + phi_buf.len() as u64;

            let mut fdi_buf = vec![];
            let mut fdi_writer = io::Cursor::new(&mut fdi_buf);
            generate_full_directory_index(&mut fdi_writer, &self.index.entries)?;

            index_writer.write_u32::<LE>(1)?; // we have path hash index
            index_writer.write_u64::<LE>(path_hash_index_offset)?;
            index_writer.write_u64::<LE>(phi_buf.len() as u64)?; // path hash index size
            index_writer.write_all(&hash(&phi_buf))?;

            index_writer.write_u32::<LE>(1)?; // we have full directory index
            index_writer.write_u64::<LE>(full_directory_index_offset)?;
            index_writer.write_u64::<LE>(fdi_buf.len() as u64)?; // path hash index size
            index_writer.write_all(&hash(&fdi_buf))?;

            let encoded_entries_size = self.index.entries.len() as u32 * ENCODED_ENTRY_SIZE;
            index_writer.write_u32::<LE>(encoded_entries_size)?;

            for entry in self.index.entries.values() {
                entry.write(
                    &mut index_writer,
                    self.version,
                    super::entry::EntryLocation::Index,
                )?;
            }

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
            encryption_uuid: None,
            encrypted: false,
            magic: super::MAGIC,
            version: self.version,
            version_major: self.version.version_major(),
            index_offset,
            index_size: index_buf.len() as u64,
            hash: index_hash,
            frozen: false,
            compression: vec![],
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

const ENCODED_ENTRY_SIZE: u32 = {
    4 // flags
    + 4 // offset
    + 4 // size
};

fn generate_path_hash_index<W: Write>(
    writer: &mut W,
    path_hash_seed: u64,
    entries: &BTreeMap<String, super::entry::Entry>,
) -> Result<(), super::Error> {
    writer.write_u32::<LE>(entries.len() as u32)?;
    let mut offset = 0u32;
    for path in entries.keys() {
        let utf16le_path = path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<_>>();
        let path_hash = fnv64(&utf16le_path, path_hash_seed);
        writer.write_u64::<LE>(path_hash)?;
        writer.write_u32::<LE>(offset)?;
        offset += ENCODED_ENTRY_SIZE;
    }

    writer.write_u32::<LE>(0)?;

    Ok(())
}

fn fnv64(data: &[u8], offset: u64) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001b3;
    let mut hash = OFFSET.wrapping_add(offset);
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn generate_full_directory_index<W: Write>(
    writer: &mut W,
    entries: &BTreeMap<String, super::entry::Entry>,
) -> Result<(), super::Error> {
    let mut offset = 0u32;
    let mut fdi = BTreeMap::new();
    for path in entries.keys() {
        let (directory, filename) = {
            let i = path.rfind('/').map(|i| i + 1); // we want to include the slash on the directory
            match i {
                Some(i) => {
                    let (l, r) = path.split_at(i);
                    (l.to_owned(), r.to_owned())
                }
                None => ("/".to_owned(), path.to_owned()),
            }
        };

        fdi.entry(directory)
            .and_modify(|d: &mut BTreeMap<String, u32>| {
                d.insert(filename.clone(), offset);
            })
            .or_insert_with(|| {
                let mut files_and_offsets = BTreeMap::new();
                files_and_offsets.insert(filename.clone(), offset);
                files_and_offsets
            });

        offset += ENCODED_ENTRY_SIZE;
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

fn pad_zeros_to_alignment(v: &mut Vec<u8>, alignment: usize) {
    assert!(alignment >= 1);
    if v.len() % alignment != 0 {
        v.extend(std::iter::repeat(0).take(((v.len() + alignment - 1) / alignment) * alignment))
    }
    assert!(v.len() % alignment == 0);
}

fn encrypt(key: Aes256, bytes: &mut [u8]) {
    use aes::cipher::BlockEncrypt;
    for chunk in bytes.chunks_mut(16) {
        key.encrypt_block(aes::Block::from_mut_slice(chunk))
    }
}
