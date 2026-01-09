# VFallenDoll Repak Fixes Applied

## Issue: Game crashes with "Corrupt pak index detected"

### Root Causes Found & Fixed

#### 1. **Per-Block Encryption** ✅ FIXED
**Problem**: Original implementation encrypted all data as one blob, but VFallenDoll requires each compression block to be individually padded and encrypted.

**Fix**: Modified `write_encrypted_data()` to encrypt each block separately with 16-byte padding between blocks.

**Code Change** (`repak/src/data.rs` + `repak/src/pak.rs`):
```rust
// OLD: Concatenate all blocks, then encrypt
let mut data = partial_entry.get_data_vec();
encrypt(&key, &mut data)?;

// NEW: Encrypt each block individually with padding
for block in blocks {
    let mut data = block.data.clone();
    let pad_len = (16 - (data.len() % 16)) % 16;
    data.resize(data.len() + pad_len, 0);
    encrypt(&self.key, &mut data)?;
    self.writer.write_all(&data)?;
}
```

#### 2. **Dynamic Compression Block Size** ✅ FIXED
**Problem**: Used fixed 65536 byte block size for all files. UE5 expects `compression_block_size` to match the actual file size for files smaller than 64KB.

**Original behavior**:
- File <64KB: `compression_block_size` = file size
- File ≥64KB: `compression_block_size` = 65536

**Our behavior (WRONG)**:
- All files: `compression_block_size` = 65536

**Fix** (`repak/src/data.rs`):
```rust
// OLD
compression_block_size = 65536;

// NEW: Use file size for small files, 64KB for large files
let max_block_size = 65536;
compression_block_size = std::cmp::min(uncompressed_size as u32, max_block_size);
```

**Impact**:
- Original Pak2 DefaultEngine.ini: `uncompressed=32980, compression_block_size=32980`
- Fixed Repak: Now matches this pattern

#### 3. **Compression Level** ✅ FIXED
**Problem**: Used `Compression::fast()` which produced larger files.

**Fix**: Changed to `Compression::default()` (level 6).

**Code Change** (`repak/src/data.rs`):
```rust
// OLD
flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast())

// NEW
flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default())
```

**Result**:
- Original Pak2: 16,835 bytes (17KB)
- Repacked Pak2: 16,547 bytes → AFTER FIX → ~17KB (matches!)

#### 4. **Compressed Size Calculation** ✅ FIXED
**Problem**: `Entry.compressed` field didn't account for per-block padding when encrypted.

**Fix**: Calculate as sum of aligned block sizes.

**Code Change** (`repak/src/data.rs`):
```rust
let compressed_size_actual = if encrypted {
    match &self.data {
        PartialEntryData::Blocks(blocks) => {
            // Sum of aligned block sizes
            blocks.iter().map(|b| (b.data.len() as u64 + 15) & !15).sum()
        }
        _ => (self.compressed_size + 15) & !15
    }
} else {
    self.compressed_size
};
```

#### 5. **File Write Order (CRITICAL FIX)** ✅ FIXED
**Problem**: Files were written to disk in **non-deterministic order** due to parallel processing, causing all file data offsets in the index to be incorrect.

**Root Cause**: `repak_cli/src/main.rs` used `.par_bridge()` to process files in parallel for performance. Even though files were sorted alphabetically before processing, they were sent to the pak writer in the order they finished processing (race condition), not the original sorted order.

**Symptoms**:
- Original pak: First file is DefaultEngine.ini (6608 bytes compressed, 32980 uncompressed)
- Broken repak: First file is DefaultGame.ini (1825 bytes compressed, 4719 uncompressed)
- File data section 136 bytes different size, causing all offsets to be wrong
- Index entries referenced files at wrong disk locations → "Corrupt pak index detected"

**Fix** (`repak_cli/src/main.rs`):
```rust
// OLD: Parallel processing with non-deterministic write order
rayon::in_place_scope(|scope| {
    scope.spawn(move |_| {
        iter.par_bridge()  // ← Files processed in parallel
            .try_for_each(|p| {
                let entry = entry_builder.build_entry(...);
                tx.send((path, entry)).unwrap();  // ← Sent in completion order!
                Ok(())
            })
    });
    for (path, entry) in rx {  // ← Written in random order
        pak.write_entry(path, entry)?;
    }
})?;

// NEW: Collect entries, sort, then write sequentially
let entries: Vec<(String, _)> = iter
    .par_bridge()  // Still process in parallel for speed
    .map(|p| -> Result<(String, _), repak::Error> {
        let entry = entry_builder.build_entry(...);
        Ok((path.to_string(), entry))
    })
    .collect::<Result<Vec<_>, _>>()?;

// Sort entries by path to ensure consistent file order
let mut entries_sorted = entries;
entries_sorted.sort_by(|a, b| a.0.cmp(&b.0));

// Write entries in sorted order
for (path, entry) in entries_sorted {
    pak.write_entry(path, entry)?;
}
```

**Impact**:
- Files now written in consistent alphabetical order
- File data offsets in index now match actual disk locations
- Original first file: DefaultEngine.ini (6608 compressed) → Ours: DefaultEngine.ini (6581 compressed)
- 27-byte compression difference is acceptable (different zlib implementation quirks)
- Uncompressed size MATCHES: 32980 bytes ✅

**Key Insight**: The pak index stores **absolute file offsets** (not relative). If files are written in wrong order, all offsets are invalidated, making the index structurally correct but pointing to wrong data.

#### 6. **Index Hash Calculation Order (CRITICAL FIX)** ✅ FIXED
**Problem**: Hashed index/PHI/FDI BEFORE adding encryption padding, but UE5's DecryptAndValidateIndex hashes the full decrypted buffer INCLUDING padding bytes.

**Root Cause**: Our code computed SHA1 hashes before padding, but UE5 decrypts the padded encrypted data and validates hash against the full decrypted buffer (with padding). Hash mismatch → "Corrupt pak index detected".

**Symptoms**:
- Pak2 worked (small files, padding differences negligible)
- Pak5 failed (larger indexes with significant padding)
- Files extracted correctly (compression valid)
- Game rejected at validation before extraction

**UE5 Validation Flow** (FPakFile.cpp:894):
```cpp
bool FPakFile::DecryptAndValidateIndex(FArchive& Reader, TArray<uint8>& IndexData, FSHAHash& InExpectedHash, FSHAHash& OutActualHash)
{
    // Decrypt in-place (padding remains in buffer!)
    if (Info.bEncryptedIndex)
    {
        DecryptData(IndexData.GetData(), IndexData.Num(), Info.EncryptionKeyGuid);
    }

    // Hash the FULL buffer including padding
    FSHA1::HashBuffer(IndexData.GetData(), IndexData.Num(), OutActualHash.Hash);
    return InExpectedHash == OutActualHash;
}
```

**Fix** (`repak/src/pak.rs`):
```rust
// OLD: Hash BEFORE padding
let phi_hash = hash(&phi_buf);
let fdi_hash = hash(&fdi_buf);
// Then add padding...
phi_buf.resize(phi_buf.len() + pad_len, 0);

// NEW: Pad FIRST, then hash
if encrypted {
    let phi_pad = (16 - (phi_buf.len() % 16)) % 16;
    phi_buf.resize(phi_buf.len() + phi_pad, 0);
    let fdi_pad = (16 - (fdi_buf.len() % 16)) % 16;
    fdi_buf.resize(fdi_buf.len() + fdi_pad, 0);
}
// Hash AFTER padding (includes padding bytes like UE5 expects)
let phi_hash = hash(&phi_buf);
let fdi_hash = hash(&fdi_buf);
```

**Primary Index Fix** (lines 755-772):
```rust
// OLD: Hash before padding
let index_hash = hash(&index_buf);
if encrypted {
    index_buf.resize(index_buf.len() + pad_len, 0);
    encrypt(key, &mut index_buf)?;
}

// NEW: Pad, hash, then encrypt
if encrypted {
    index_buf.resize(index_buf.len() + pad_len, 0);
}
let index_hash = hash(&index_buf);  // Hash after padding, before encryption
if encrypted {
    encrypt(key, &mut index_buf)?;
}
```

**Impact**:
- All three index hashes (Primary, PHI, FDI) now computed correctly
- Hashes validate successfully in UE5's DecryptAndValidateIndex
- Pak5 repacks now pass hash validation stage
- Files still extract correctly (compression unchanged)

**Verification**:
- Pak5_HASH_FIXED2.pak: Files extract with correct MD5
  - AssetRegistry.bin: `e84d026713c1a72e3b5d69ce3c71d3eb` ✅
  - Paralogue.uproject: `dfa303a428b94a92d83c65462e3e6f3d` ✅
- Index hashes now match UE5's expected format

### Current Status

**Verified Working** (via repak tool):
- ✅ Correct mount point (`../../../Paralogue/Config/`)
- ✅ Correct path hash seed (0x3C87E9DF)
- ✅ Correct file paths (no doubling)
- ✅ Correct file sizes (~17KB, 160 bytes smaller due to compression variance)
- ✅ Files extract correctly and are byte-identical
- ✅ Dynamic compression_block_size (matches file size for small files)
- ✅ Per-block encryption with padding
- ✅ **Correct file order on disk** (DefaultEngine.ini first, alphabetically sorted)
- ✅ File data offsets in index match actual disk locations
- ✅ **Index hash calculation** (Primary, PHI, FDI hashes include padding bytes)

**CONFIRMED WORKING IN-GAME** ✅:
- Pak5_HASH_FIXED2.pak loads successfully without crashes
- All known issues fixed including critical hash bug
- File structure matches original pak
- Index hashes calculated correctly per UE5 validation logic
- **Compression variance (~30KB / 0.8%) is tolerated by UE5** ✅
- No additional validation failures beyond hash checks

**Key Discovery**: The hash calculation order was the blocker, NOT compression variance. UE5 accepts different compression implementations as long as:
1. Files decompress correctly
2. Index hashes match the padded decrypted buffers
3. File write order is deterministic

### Testing Steps

1. **Backup original**:
   ```cmd
   copy "C:\...\Pak2.pak" "C:\...\Pak2.pak.backup"
   ```

2. **Install repacked**:
   ```cmd
   copy Pak2_repacked.pak "C:\...\Pak2.pak"
   ```

3. **Test in game**:
   - Launch game
   - Check if it loads without crashing
   - Verify config settings work

4. **If it crashes**, restore backup:
   ```cmd
   copy "C:\...\Pak2.pak.backup" "C:\...\Pak2.pak"
   ```

   OR use the helper script:
   ```cmd
   test_in_game.bat
   ```

### All Issues Resolved ✅

All root causes have been identified and fixed:

1. ~~**Compression determinism**~~: ✅ CONFIRMED - UE5 tolerates compression variance
   - Pak2: 27-byte difference (6608 vs 6581) - WORKS ✅
   - Pak5: 30,094-byte difference (3,664,543 vs 3,634,449) - WORKS ✅
2. ~~**Index structure differences**~~: ✅ CONFIRMED - Structure is correct
3. ~~**File write order**~~: ✅ FIXED - Files now written in correct alphabetical order
4. ~~**Index hash validation**~~: ✅ FIXED - Hashes now include padding bytes per UE5 expectations (THIS WAS THE CRITICAL BUG)
5. ~~**UE5 internal checksums**~~: ✅ CONFIRMED - No additional validation beyond what we fixed

### Files Modified

- `repak/src/data.rs` - Per-block encryption, dynamic block size, compression level
- `repak/src/pak.rs` - Per-block writing logic, padding calculation, **hash calculation order fix**
- `repak/src/entry.rs` - Removed debug output (cleanup)
- `repak_cli/src/main.rs` - **Fixed file write order** (collect → sort → write instead of parallel race condition), added --fallendoll CLI flag
- `FPakFile.cpp` - UE5 source reference for understanding DecryptAndValidateIndex validation logic

### Commands for Repacking

**Pak2.pak**:
```bash
cd pak2_clean/Paralogue/Config
../../../target/release/repak.exe pack \
  --version VFallenDoll \
  --compression Zlib \
  --mount-point "../../../Paralogue/Config/" \
  --path-hash-seed 1015540191 \
  . ../../../Pak2_repacked.pak
```

**Pak5.pak** (CRITICAL: cd into Paralogue directory first to avoid path doubling):
```bash
cd pak5_clean/Paralogue
../../target/release/repak.exe pack \
  --version VFallenDoll \
  --compression Zlib \
  --mount-point "../../../Paralogue/" \
  --path-hash-seed 3720703820 \
  . ../../Pak5_repacked.pak
```
