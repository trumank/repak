# VFallenDoll Support for Repak

This fork adds support for **VFallenDoll** - a custom PAK file encryption used in Unreal Engine 5.5 games with FallenDoll anti-tamper protection.

## What is VFallenDoll?

VFallenDoll is a PAK file format variant (version 11) that uses a custom AES-256 block cipher with non-standard S-boxes and T-tables. It encrypts only the PAK index (not file data), making it different from standard UE5 encryption.

**Tested Game**: Operation Lovecraft: Fallen Doll (UE 5.5)

## Features

- ✅ **Full VFallenDoll cipher implementation** - 14-round custom AES-256 variant
- ✅ **Index-only encryption** - File data remains unencrypted per VFallenDoll spec
- ✅ **Easy CLI usage** - Simple `--fallendoll` flag for all operations
- ✅ **Verified working** - Tested on 3 PAK files (16KB-19MB) with in-game validation
- ✅ **Compression variance tolerant** - UE5 accepts 0.8-2% size differences

## Installation

### Build from source:
```bash
cargo build --release
```

Binary location: `target/release/repak.exe`

### Requirements:
- Rust 1.70+
- Windows/Linux/macOS

## Usage

All standard repak commands work with the `--fallendoll` flag:

### View PAK Info
```bash
repak --fallendoll info Pak1.pak
```

### List Files
```bash
repak --fallendoll list Pak1.pak
```

### Extract Single File
```bash
repak --fallendoll get Pak1.pak "Engine/Config/BaseEngine.ini"
```

### Extract All Files
```bash
repak --fallendoll unpack Pak1.pak ./output_dir
```

### Repack PAK
```bash
# IMPORTANT: cd into the directory that matches the mount point structure
cd extracted/Engine/Content
repak pack --version VFallenDoll --compression Zlib \
  --mount-point "../../../Engine/Content/" \
  --path-hash-seed 123456789 \
  . ../../../Pak1_repacked.pak
```

## Critical: Mount Point & Directory Structure

The mount point MUST match your directory structure to avoid path doubling:

**Example 1: Config PAK**
```bash
# Mount point: ../../../Paralogue/Config/
# Directory structure: pak_clean/Paralogue/Config/DefaultEngine.ini

cd pak_clean/Paralogue/Config
repak pack --version VFallenDoll --mount-point "../../../Paralogue/Config/" ...
```

**Example 2: Content PAK**
```bash
# Mount point: ../../../Paralogue/
# Directory structure: pak_clean/Paralogue/AssetRegistry.bin

cd pak_clean/Paralogue
repak pack --version VFallenDoll --mount-point "../../../Paralogue/" ...
```

## Finding PAK Parameters

To get the correct `--path-hash-seed` and `--mount-point` from an existing PAK:

```bash
repak --fallendoll info original.pak
```

Output:
```
mount point: ../../../Paralogue/Config/
path hash seed: Some(3C87E9DF)  # Use decimal: 1015540191
```

## Technical Details

### Cipher Specifications
- **Algorithm**: Custom 14-round block cipher
- **Block Size**: 128 bits (16 bytes)
- **Key Size**: 256 bits
- **Mode**: ECB with manual block handling
- **Padding**: PKCS#7-style zero padding to 16-byte boundaries
- **S-boxes**: 5 custom non-standard substitution boxes
- **T-tables**: Pre-computed transformation tables for performance

### Encryption Scope
- ✅ **Primary Index**: Encrypted (mount point, entry count, metadata)
- ✅ **Path Hash Index (PHI)**: Encrypted (fast file lookup)
- ✅ **Full Directory Index (FDI)**: Encrypted (directory hierarchy)
- ❌ **File Data**: NOT encrypted (can be read directly from disk)

### Key Differences from Standard Repak
1. **Hash Calculation**: Hashes computed AFTER padding (critical for validation)
2. **Per-block Encryption**: Multi-block files encrypted block-by-block with padding
3. **Dynamic Block Size**: Files <64KB use file size as block size, not fixed 65536
4. **Deterministic File Order**: Files written in alphabetical order to match index offsets

## Verification

All three test PAKs passed in-game validation:

| PAK | Files | Size | Compression Variance | Status |
|-----|-------|------|---------------------|--------|
| Pak2.pak | 6 configs | 16KB | 2.0% smaller | ✅ Works |
| Pak3.pak | 159 plugins | 19MB | 0.8% smaller | ✅ Works |
| Pak5.pak | 2 assets | 3.6MB | 0.8% smaller | ✅ Works |

## Troubleshooting

### "Corrupt pak index detected"
- **Check mount point** matches your directory structure
- **Verify path-hash-seed** matches original PAK
- **Ensure deterministic file order** (repak handles this automatically)

### Files extract correctly but game crashes
- Usually means mount point mismatch causing path doubling
- Compare original paths: `repak --fallendoll list original.pak`
- With your paths: `repak --fallendoll list repacked.pak`

### Size differences
- 0.8-2% compression variance is normal and accepted by UE5
- Different zlib implementations produce slightly different output
- As long as files decompress identically, it's fine

## Implementation Details

See [`FIXES_APPLIED.md`](FIXES_APPLIED.md) for comprehensive documentation of all 6 critical fixes:

1. Per-block encryption with padding
2. Dynamic compression block size
3. Compression level optimization
4. Compressed size calculation
5. Deterministic file write order
6. **Index hash calculation order** (THE CRITICAL BUG)

## Files Modified

- `repak/src/fallendoll.rs` - Complete cipher implementation (134KB)
- `repak/src/pak.rs` - Hash calculation fix, encryption logic
- `repak/src/data.rs` - Per-block handling, dynamic sizing
- `repak/src/lib.rs` - VFallenDoll version enum, key types
- `repak_cli/src/main.rs` - CLI flag support

## Contributing

This fork is specifically for VFallenDoll support. For general repak issues, see the [upstream repository](https://github.com/trumank/repak).

## Disclaimer

This tool is for educational purposes and legitimate game modding. Respect copyright laws and game EULAs.

## Credits

- **Original Repak**: [trumank/repak](https://github.com/trumank/repak)
- **VFallenDoll Support**: Reverse engineering and implementation
- **Cipher Analysis**: Extracted from Operation Lovecraft: Fallen Doll
- **UE5 Reference**: Epic Games Unreal Engine source

## License

Same as upstream repak (see main LICENSE file).
