use super::{Version, VersionMajor};
use hashbrown::HashMap;
use std::io::{self, Seek};

#[derive(Debug)]
pub struct PakReader<R: io::Read + io::Seek> {
    pak: Pak,
    reader: R,
}
#[derive(Debug)]
pub struct Pak {
    version: Version,
    mount_point: String,
    key: Option<aes::Aes256Dec>,
    index: Index,
}

#[derive(Debug)]
pub enum Index {
    V1(IndexV1),
    V2(IndexV2),
}

impl Index {
    fn entries(&self) -> &HashMap<String, super::entry::Entry> {
        match self {
            Index::V1(index) => &index.entries,
            Index::V2(index) => &index.entries_by_path,
        }
    }
}

#[derive(Debug)]
pub struct IndexV1 {
    entries: HashMap<String, super::entry::Entry>,
}

#[derive(Debug)]
pub struct IndexV2 {
    path_hash_seed: u64,
    path_hash_index: Option<Vec<u8>>,
    full_directory_index: Option<HashMap<String, HashMap<String, u32>>>,
    encoded_entries: Vec<u8>,
    entries_by_path: HashMap<String, super::entry::Entry>,
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

impl<R: io::Seek + io::Read> PakReader<R> {
    pub fn into_reader(self) -> R {
        self.reader
    }
}

impl<R: io::Read + io::Seek> PakReader<R> {
    pub fn new_any(mut reader: R, key: Option<aes::Aes256Dec>) -> Result<Self, super::Error> {
        for ver in Version::iter() {
            match PakReader::new(&mut reader, ver, key.clone()) {
                Ok(pak) => {
                    return Ok(PakReader { pak, reader });
                }
                _ => continue,
            }
        }
        Err(super::Error::Other("version unsupported"))
    }

    pub fn new(
        mut reader: R,
        version: super::Version,
        key: Option<aes::Aes256Dec>,
    ) -> Result<Pak, super::Error> {
        use super::ext::ReadExt;
        use byteorder::{ReadBytesExt, LE};
        // read footer to get index, encryption & compression info
        reader.seek(io::SeekFrom::End(-version.size()))?;
        let footer = super::footer::Footer::new(&mut reader, version)?;
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
                let mut directories = HashMap::with_capacity(dir_count);
                for _ in 0..dir_count {
                    let dir_name = fdi.read_string()?;
                    let file_count = fdi.read_u32::<LE>()? as usize;
                    let mut files = HashMap::with_capacity(file_count);
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

            let mut entries_by_path = HashMap::new();
            if let Some(fdi) = &full_directory_index {
                let mut encoded_entries = io::Cursor::new(&encoded_entries);
                for (dir_name, dir) in fdi {
                    for (file_name, encoded_offset) in dir {
                        encoded_entries.seek(io::SeekFrom::Start(*encoded_offset as u64))?;
                        let entry =
                            super::entry::Entry::new_encoded(&mut encoded_entries, version)?;

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
            let mut entries = HashMap::with_capacity(len);
            for _ in 0..len {
                entries.insert(
                    index.read_string()?,
                    super::entry::Entry::new(&mut index, version)?,
                );
            }
            Index::V1(IndexV1 { entries })
        };

        Ok(Pak {
            version,
            mount_point,
            key,
            index,
        })
    }

    pub fn version(&self) -> super::Version {
        self.pak.version
    }

    pub fn mount_point(&self) -> &str {
        &self.pak.mount_point
    }

    pub fn get(&mut self, path: &str) -> Result<Vec<u8>, super::Error> {
        let mut data = Vec::new();
        self.read(path, &mut data)?;
        Ok(data)
    }

    pub fn read<W: io::Write>(&mut self, path: &str, writer: &mut W) -> Result<(), super::Error> {
        match self.pak.index.entries().get(path) {
            Some(entry) => entry.read(
                &mut self.reader,
                self.pak.version,
                self.pak.key.as_ref(),
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
