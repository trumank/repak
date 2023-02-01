# repak

fork of https://github.com/bananaturtlesandwich/unpak

## compatibility

| UE Version | Version | Version Feature       | Read               | Write              |
|------------|---------|-----------------------|--------------------|--------------------|
|            | 1       | Initial               | :grey_question:    | :x:                |
| 4.0-4.2    | 2       | NoTimestamps          | :heavy_check_mark: | :x:                |
| 4.3-4.15   | 3       | CompressionEncryption | :heavy_check_mark: | :x:                |
| 4.16-4.19  | 4       | IndexEncryption       | :heavy_check_mark: | :x:                |
| 4.20       | 5       | RelativeChunkOffsets  | :heavy_check_mark: | :x:                |
|            | 6       | DeleteRecords         | :grey_question:    | :x:                |
| 4.21       | 7       | EncryptionKeyGuid     | :heavy_check_mark: | :x:                |
| 4.22       | 8A      | FNameBasedCompression | :heavy_check_mark: | :x:                |
| 4.23-4.24  | 8B      | FNameBasedCompression | :heavy_check_mark: | :heavy_check_mark: |
| 4.25       | 9       | FrozenIndex           | :heavy_check_mark: | :x:                |
|            | 10      | PathHashIndex         | :grey_question:    | :x:                |
| 4.26-4.27  | 11      | Fnv64BugFix           | :heavy_check_mark: | :x:                |

Supports reading encrypted (both index and/or data) and compressed paks.
Writing is still a work in progress, but is functional enough for most recent
Unreal Engine versions.
