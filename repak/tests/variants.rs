use repak::PakVariant;

#[test]
fn test_variant_encryption() {
    let test_data = vec![1u8; 8192];
    let key = get_test_key();
    
    // Test NetEase variant
    {
        let mut pak = repak::PakBuilder::new()
            .variant(PakVariant::NetEase)
            .key(key)
            .writer(std::io::Cursor::new(Vec::new()), 
                   repak::Version::V11, 
                   "".to_string(), 
                   None);
            
        pak.write_file("test.uasset", test_data.clone()).unwrap();
        let result = pak.into_writer().into_inner();
        
        // Verify only first 4KB is encrypted
        assert_ne!(&result[..4096], &test_data[..4096]);
        assert_eq!(&result[4096..], &test_data[4096..]);
    }
    
    // Test Marvel Rivals variant
    {
        let mut pak = repak::PakBuilder::new()
            .variant(PakVariant::MarvelRivals)
            .key(key)
            .writer(std::io::Cursor::new(Vec::new()), 
                   repak::Version::V11, 
                   "".to_string(), 
                   None);
            
        pak.write_file("Content/Test/test.uasset", test_data.clone()).unwrap();
        let result = pak.into_writer().into_inner();
        
        // Verify the encrypted size is aligned to 64 bytes
        let encrypted_size = result.len();
        assert_eq!(encrypted_size & 0x3F, 0);
    }
}

fn get_test_key() -> aes::Aes256 {
    use aes::cipher::KeyInit;
    use base64::{engine::general_purpose, Engine as _};
    
    general_purpose::STANDARD
        .decode(include_str!("crypto.json"))
        .as_ref()
        .map_err(|_| repak::Error::Aes)
        .and_then(|bytes| aes::Aes256::new_from_slice(bytes).map_err(|_| repak::Error::Aes))
        .unwrap()
}
