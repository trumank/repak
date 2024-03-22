# repak

Library and CLI tool for working with Unreal Engine .pak files.

 - Supports reading and writing a wide range of versions
 - Easy to use API while providing low level control:
   - Only parses index initially and reads file data upon request
   - Can rewrite index in place to perform append or delete operations without rewriting entire pak

`repak` CLI
 - Sane handling of mount points: defaults to `../../../` but can be configured via flag
 - 2x faster unpacking over `UnrealPak`. As much as 30x faster has been observed (on Linux unpacked to ramdisk)
 - Unpacking is guarded against malicious pak that attempt to write to parent directories

## cli
```console
$ repak --help
Usage: repak [OPTIONS] <COMMAND>

Commands:
  info       Print .pak info
  list       List .pak files
  hash-list  List .pak files and the SHA256 of their contents. Useful for finding differences between paks
  unpack     Unpack .pak file
  pack       Pack directory into .pak file
  get        Reads a single file to stdout
  help       Print this message or the help of the given subcommand(s)

Options:
  -a, --aes-key <AES_KEY>  256 bit AES encryption key as base64 or hex string if the pak is encrypted
  -h, --help               Print help
  -V, --version            Print version
```

### packing
```console
$ find mod
mod
mod/assets
mod/assets/AssetA.uasset
mod/assets/AssetA.uexp

$ repak pack -v mod
packing assets/AssetA.uasset
packing assets/AssetA.uexp
Packed 4 files to mod.pak

$ repak list mod.pak
assets/AssetA.uasset
assets/AssetA.uexp
```

### unpacking
```console
$ repak --aes-key 0x12345678 unpack MyEncryptedGame.pak
Unpacked 12345 files to MyEncryptedGame from MyEncryptedGame.pak
```

## compatibility

| UE Version   | Version | Version Feature       | Read               | Write                  |
|--------------|---------|-----------------------|--------------------|------------------------|
|              | 1       | Initial               | :grey_question:    | :grey_question:        |
| 4.0-4.2      | 2       | NoTimestamps          | :heavy_check_mark: | :heavy_check_mark:     |
| 4.3-4.15     | 3       | CompressionEncryption | :heavy_check_mark: | :heavy_check_mark:     |
| 4.16-4.19    | 4       | IndexEncryption       | :heavy_check_mark: | :heavy_check_mark:     |
| 4.20         | 5       | RelativeChunkOffsets  | :heavy_check_mark: | :heavy_check_mark:     |
|              | 6       | DeleteRecords         | :grey_question:    | :grey_question:        |
| 4.21         | 7       | EncryptionKeyGuid     | :heavy_check_mark: | :heavy_check_mark:     |
| 4.22         | 8A      | FNameBasedCompression | :heavy_check_mark: | :heavy_check_mark:     |
| 4.23-4.24    | 8B      | FNameBasedCompression | :heavy_check_mark: | :heavy_check_mark:     |
| 4.25         | 9       | FrozenIndex           | :heavy_check_mark: | :heavy_check_mark:[^1] |
|              | 10      | PathHashIndex         | :grey_question:    | :grey_question:        |
| 4.26-5.3[^2] | 11      | Fnv64BugFix           | :heavy_check_mark: | :heavy_check_mark:     |

| Feature         | Read               | Write           |
|-----------------|--------------------|-----------------|
| Compression     | :heavy_check_mark: | :wavy_dash:[^3] |
| Encrypted Index | :heavy_check_mark: | :x:             |
| Encrypted Data  | :heavy_check_mark: | :x:             |


[^1]: Except for paks compressed using frozen index which has significant
    complexity and only existed for UE 4.25 anyway.
[^2]: As of writing. Later versions are likely supported but untested.
[^3]: Zlib, Gzip, and Zstd are supported. Not all compression algorithms are
    available in all games.

Supports reading encrypted (both index and/or data) and compressed paks.
Writing does not support compression or encryption yet.

## notes

### determinism

As far as I can tell, the index is not necessarily written deterministically by `UnrealPak`. `repak` uses `BTreeMap` in place of `HashMap` to deterministically write the index and *happens* to rewrite the test paks in the same order, but this more likely than not stops happening on larger pak files.

### full directory index

`UnrealPak` includes a directory entry in the full directory index for all parent directories back to the pak root for a given file path regardless of whether those directories contain any files or just other directories. `repak` only includes directories that contain files. So far no functional differences have been observed as a result.

## acknowledgements
- [unpak](https://github.com/bananaturtlesandwich/unpak): original crate featuring read-only pak operations
- [rust-u4pak](https://github.com/panzi/rust-u4pak)'s README detailing the pak file layout
- [jieyouxu](https://github.com/jieyouxu) for serialization implementation of the significantly more complex V11 index
