use super::ext::{ReadExt, WriteExt};
use super::{Version, VersionMajor};
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
            Index::V2(index) => &index.entries_by_path,
        }
    }

    fn add_entry(&mut self, path: &str, entry: super::entry::Entry) {
        match self {
            Index::V1(index) => index.entries.insert(path.to_string(), entry),
            Index::V2(_index) => todo!(),
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
    path_hash_index: Option<Vec<u8>>,
    full_directory_index: Option<BTreeMap<String, BTreeMap<String, u32>>>,
    encoded_entries: Vec<u8>,
    entries_by_path: BTreeMap<String, super::entry::Entry>,
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

            let path_hash_index = if index.read_u32::<LE>()? != 0 {
                let path_hash_index_offset = index.read_u64::<LE>()?;
                let path_hash_index_size = index.read_u64::<LE>()?;
                let _path_hash_index_hash = index.read_len(20)?;

                reader.seek(io::SeekFrom::Start(path_hash_index_offset))?;
                let mut path_hash_index = reader.read_len(path_hash_index_size as usize)?;
                // TODO verify hash

                if footer.encrypted {
                    decrypt(&key, &mut path_hash_index)?;
                }
                Some(path_hash_index)
            } else {
                None
            };

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

                        // entry next to file contains full metadata
                        //reader.seek(io::SeekFrom::Start(entry.offset))?;
                        //let _ = super::entry::Entry::new(&mut reader, version)?;

                        // concat directory with file name to match IndexV1 but should provide a more direct access method
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
                path_hash_index,
                full_directory_index,
                encoded_entries,
                entries_by_path,
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

        let mut index_cur = std::io::Cursor::new(vec![]);
        index_cur.write_string(&self.mount_point)?;

        match &self.index {
            Index::V1(index) => {
                index_cur.write_u32::<LE>(index.entries.len() as u32)?;
                for (path, entry) in &index.entries {
                    index_cur.write_string(path)?;
                    entry.write(
                        &mut index_cur,
                        self.version,
                        super::entry::EntryLocation::Index,
                    )?;
                }
            }
            Index::V2(_index) => todo!(),
        }

        let index_data = index_cur.into_inner();

        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(&index_data);

        let footer = super::footer::Footer {
            encryption_uuid: None,
            encrypted: false,
            magic: super::MAGIC,
            version: self.version,
            version_major: self.version.version_major(),
            index_offset,
            index_size: index_data.len() as u64,
            hash: hasher.finalize().into(),
            frozen: false,
            compression: vec![],
        };

        writer.write_all(&index_data)?;

        footer.write(writer)?;

        Ok(())
    }
}

mod test {
    #[test]
    fn test_rewrite_pak() {
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
        assert_eq!(bytes.to_vec(), out_bytes);
    }
}
