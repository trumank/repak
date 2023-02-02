use super::ext::{ReadExt, WriteExt};
use super::{Version, VersionMajor};
use aes::Aes256Enc;
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::collections::BTreeMap;
use std::io::{self, Read, Seek, Write};

#[derive(Debug)]
pub struct PakReader<R: Read + Seek> {
    pak: Pak,
    reader: R,
    key: Option<aes::Aes256Dec>,
}

#[derive(Debug)]
pub struct PakWriter<W: Write + Seek> {
    pak: Pak,
    writer: W,
    key: Option<aes::Aes256Enc>,
}

#[derive(Debug)]
pub struct Pak {
    version: Version,
    mount_point: String,
    index: Index,
}

impl Pak {
    fn new(version: Version, mount_point: String) -> Self {
        Pak {
            version,
            mount_point,
            index: Index::new(version),
        }
    }
}

#[derive(Debug)]
pub enum Index {
    V1(IndexV1),
    V2(IndexV2),
}

impl Index {
    fn new(version: Version) -> Self {
        if version < Version::V10 {
            Self::V1(IndexV1::default())
        } else {
            Self::V2(IndexV2::default())
        }
    }

    fn entries(&self) -> &BTreeMap<String, super::entry::Entry> {
        match self {
            Index::V1(index) => &index.entries,
            Index::V2(index) => &index.entries,
        }
    }

    fn add_entry(&mut self, path: &str, entry: super::entry::Entry) {
        match self {
            Index::V1(index) => index.entries.insert(path.to_string(), entry),
            Index::V2(index) => index.entries.insert(path.to_string(), entry),
        };
    }
}

#[derive(Debug, Default)]
pub struct IndexV1 {
    entries: BTreeMap<String, super::entry::Entry>,
}

#[derive(Debug, Default)]
pub struct IndexV2 {
    path_hash_seed: u64,
    entries: BTreeMap<String, super::entry::Entry>,
}

fn decrypt(key: &Option<aes::Aes256Dec>, bytes: &mut [u8]) -> Result<(), super::Error> {
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

impl<R: Read + Seek> PakReader<R> {
    pub fn new_any(mut reader: R, key: Option<aes::Aes256Dec>) -> Result<Self, super::Error> {
        for ver in Version::iter() {
            match Pak::read(&mut reader, ver, key.clone()) {
                Ok(pak) => {
                    return Ok(PakReader { pak, reader, key });
                }
                _ => continue,
            }
        }
        Err(super::Error::Other("version unsupported"))
    }

    pub fn into_reader(self) -> R {
        self.reader
    }

    pub fn version(&self) -> super::Version {
        self.pak.version
    }

    pub fn mount_point(&self) -> &str {
        &self.pak.mount_point
    }

    pub fn get(&mut self, path: &str) -> Result<Vec<u8>, super::Error> {
        let mut data = Vec::new();
        self.read_file(path, &mut data)?;
        Ok(data)
    }

    pub fn read_file<W: io::Write>(
        &mut self,
        path: &str,
        writer: &mut W,
    ) -> Result<(), super::Error> {
        match self.pak.index.entries().get(path) {
            Some(entry) => entry.read_file(
                &mut self.reader,
                self.pak.version,
                self.key.as_ref(),
                writer,
            ),
            None => Err(super::Error::Other("no file found at given path")),
        }
    }

    pub fn files(&self) -> std::vec::IntoIter<String> {
        self.pak
            .index
            .entries()
            .keys()
            .cloned()
            .collect::<Vec<String>>()
            .into_iter()
    }
}

impl<W: Write + io::Seek> PakWriter<W> {
    pub fn new(
        writer: W,
        key: Option<aes::Aes256Enc>,
        version: Version,
        mount_point: String,
    ) -> Self {
        PakWriter {
            pak: Pak::new(version, mount_point),
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
        key: Option<aes::Aes256Dec>,
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

            Index::V2(IndexV2 {
                path_hash_seed,
                entries: entries_by_path,
            })
        } else {
            let mut entries = BTreeMap::new();
            for _ in 0..len {
                entries.insert(
                    index.read_string()?,
                    super::entry::Entry::read(&mut index, version)?,
                );
            }
            Index::V1(IndexV1 { entries })
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
        _key: Option<aes::Aes256Enc>,
    ) -> Result<(), super::Error> {
        let index_offset = writer.stream_position()?;

        let mut index_buf = vec![];
        let mut index_writer = io::Cursor::new(&mut index_buf);
        index_writer.write_string(&self.mount_point)?;

        let secondary_index = match &self.index {
            Index::V1(index) => {
                let record_count = index.entries.len() as u32;
                index_writer.write_u32::<LE>(record_count)?;
                for (path, entry) in &index.entries {
                    index_writer.write_string(path)?;
                    entry.write(
                        &mut index_writer,
                        self.version,
                        super::entry::EntryLocation::Index,
                    )?;
                }
                None
            }
            Index::V2(index) => {
                let record_count = index.entries.len() as u32;
                index_writer.write_u32::<LE>(record_count)?;
                index_writer.write_u64::<LE>(index.path_hash_seed)?;

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
                    size += index.entries.len() as u64 * {
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
                generate_path_hash_index(&mut phi_writer, index.path_hash_seed, &index.entries)?;

                let full_directory_index_offset = path_hash_index_offset + phi_buf.len() as u64;

                let mut fdi_buf = vec![];
                let mut fdi_writer = io::Cursor::new(&mut fdi_buf);
                generate_full_directory_index(&mut fdi_writer, &index.entries)?;

                index_writer.write_u32::<LE>(1)?; // we have path hash index
                index_writer.write_u64::<LE>(path_hash_index_offset)?;
                index_writer.write_u64::<LE>(phi_buf.len() as u64)?; // path hash index size
                index_writer.write_all(&hash(&phi_buf))?;

                index_writer.write_u32::<LE>(1)?; // we have full directory index
                index_writer.write_u64::<LE>(full_directory_index_offset)?;
                index_writer.write_u64::<LE>(fdi_buf.len() as u64)?; // path hash index size
                index_writer.write_all(&hash(&fdi_buf))?;

                let encoded_entries_size = index.entries.len() as u32 * ENCODED_ENTRY_SIZE;
                index_writer.write_u32::<LE>(encoded_entries_size)?;

                for entry in index.entries.values() {
                    entry.write(
                        &mut index_writer,
                        self.version,
                        super::entry::EntryLocation::Index,
                    )?;
                }

                index_writer.write_u32::<LE>(0)?;

                Some((phi_buf, fdi_buf))
            }
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

fn encrypt(key: Aes256Enc, bytes: &mut [u8]) {
    use aes::cipher::BlockEncrypt;
    for chunk in bytes.chunks_mut(16) {
        key.encrypt_block(aes::Block::from_mut_slice(chunk))
    }
}

#[cfg(test)]
mod test {
    use super::IndexV2;

    #[test]
    fn test_rewrite_pak_v8b() {
        use std::io::Cursor;
        let bytes = include_bytes!("../tests/packs/pack_v8b.pak");

        let mut reader = super::PakReader::new_any(Cursor::new(bytes), None).unwrap();
        let writer = Cursor::new(vec![]);
        let mut pak_writer = super::PakWriter::new(
            writer,
            None,
            super::Version::V8B,
            reader.mount_point().to_owned(),
        );

        for path in reader.files() {
            let data = reader.get(&path).unwrap();
            pak_writer
                .write_file(&path, &mut std::io::Cursor::new(data))
                .unwrap();
        }

        let out_bytes = pak_writer.write_index().unwrap().into_inner();
        assert_eq!(&bytes[..], &out_bytes[..]);
    }

    #[test]
    fn test_rewrite_pak_v11() {
        use std::io::Cursor;
        let bytes = include_bytes!("../tests/packs/pack_v11.pak");

        let mut reader = super::PakReader::new_any(Cursor::new(bytes), None).unwrap();
        let writer = Cursor::new(vec![]);
        let mut pak_writer = super::PakWriter::new(
            writer,
            None,
            super::Version::V11,
            reader.mount_point().to_owned(),
        );

        for path in reader.files() {
            let data = reader.get(&path).unwrap();
            pak_writer
                .write_file(&path, &mut std::io::Cursor::new(data))
                .unwrap();
        }

        // There's a caveat: UnrealPak uses the absolute path (in UTF-16LE) of the output pak
        // passed to strcrc32() as the PathHashSeed. We don't want to require the user to do this.
        if let super::Index::V2(index) = pak_writer.pak.index {
            pak_writer.pak.index = super::Index::V2(IndexV2 {
                path_hash_seed: u64::from_le_bytes([
                    0x7D, 0x5A, 0x5C, 0x20, 0x00, 0x00, 0x00, 0x00,
                ]),
                ..index
            });
        } else {
            panic!()
        };

        let out_bytes = pak_writer.write_index().unwrap().into_inner();

        assert_eq!(&bytes[..], &out_bytes[..]);
    }
}
