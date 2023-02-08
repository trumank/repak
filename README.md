# repak

fork of https://github.com/bananaturtlesandwich/unpak

## compatibility

| UE Version | Version | Version Feature       | Read               | Write              |
|------------|---------|-----------------------|--------------------|--------------------|
|            | 1       | Initial               | :grey_question:    | :grey_question:    |
| 4.0-4.2    | 2       | NoTimestamps          | :heavy_check_mark: | :heavy_check_mark: |
| 4.3-4.15   | 3       | CompressionEncryption | :heavy_check_mark: | :heavy_check_mark: |
| 4.16-4.19  | 4       | IndexEncryption       | :heavy_check_mark: | :heavy_check_mark: |
| 4.20       | 5       | RelativeChunkOffsets  | :heavy_check_mark: | :heavy_check_mark: |
|            | 6       | DeleteRecords         | :grey_question:    | :grey_question:    |
| 4.21       | 7       | EncryptionKeyGuid     | :heavy_check_mark: | :heavy_check_mark: |
| 4.22       | 8A      | FNameBasedCompression | :heavy_check_mark: | :heavy_check_mark: |
| 4.23-4.24  | 8B      | FNameBasedCompression | :heavy_check_mark: | :heavy_check_mark: |
| 4.25       | 9       | FrozenIndex           | :heavy_check_mark: | :heavy_check_mark: |
|            | 10      | PathHashIndex         | :grey_question:    | :grey_question:    |
| 4.26-4.27  | 11      | Fnv64BugFix           | :heavy_check_mark: | :heavy_check_mark: |

| Feature         | Read               | Write |
|-----------------|--------------------|-------|
| Compression     | :heavy_check_mark: | :x:   |
| Encrypted Index | :heavy_check_mark: | :x:   |
| Encrypted Data  | :heavy_check_mark: | :x:   |

Supports reading encrypted (both index and/or data) and compressed paks.
Writing does not support compression or encryption yet.
