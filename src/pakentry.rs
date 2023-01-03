pub struct PakEntry {
    pub offset: u64,
    pub compressed: u64,
    pub decompressed: u64,
    pub compression_method: super::Compression,
    pub hash: [u8; 20],
    pub compression_blocks: Vec<Block>,
    pub flags: Vec<u8>,
    pub block_size: u32,
}

pub struct Block {
    /// start offset relative to the start of the entry header
    pub offset: u64,
    /// size of the compressed block
    pub size: u64,
}
