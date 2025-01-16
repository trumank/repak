use aes::cipher::BlockEncrypt;
use blake3::Hasher;

/// Size limit for NetEase variant encryption (4KB)
const NETEASE_ENCRYPTION_LIMIT: u64 = 0x1000;

/// Calculates how many bytes should be encrypted based on the variant and path
pub fn calculate_encrypted_bytes_count(variant: super::PakVariant, path: &str, total_size: u64) -> u64 {
    match variant {
        super::PakVariant::Standard => total_size,
        super::PakVariant::NetEase => std::cmp::min(NETEASE_ENCRYPTION_LIMIT, total_size),
        super::PakVariant::MarvelRivals => {
            let mut hasher = Hasher::new();
            hasher.update(&0x44332211u32.to_le_bytes());
            hasher.update(path.to_lowercase().as_bytes());
            
            let hash = hasher.finalize();
            let first_u64 = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap());
            
            let encrypted_size = (63 * (first_u64 % 0x3D) + 319) & 0xFFFFFFFFFFFFFFC0;
            std::cmp::min(encrypted_size, total_size)
        }
    }
}

/// Encrypts a portion of the data based on the variant and path
#[cfg(feature = "encryption")]
pub(crate) fn encrypt(key: &super::Key, bytes: &mut [u8], variant: super::PakVariant, path: &str) -> Result<(), super::Error> {
    if let super::Key::Some(key) = key {
        let encrypt_size = calculate_encrypted_bytes_count(
            variant,
            path,
            bytes.len() as u64
        ) as usize;

        // Ensure encrypt_size is aligned to AES block size (16 bytes)
        let encrypt_size = encrypt_size & !0xF;
        
        for chunk in bytes[..encrypt_size].chunks_mut(16) {
            if chunk.len() == 16 {
                chunk.chunks_mut(4).for_each(|c| c.reverse());
                key.encrypt_block(aes::Block::from_mut_slice(chunk));
                chunk.chunks_mut(4).for_each(|c| c.reverse());
            }
        }
        Ok(())
    } else {
        Err(super::Error::Encrypted)
    }
}