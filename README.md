# unpak
## a no-nonsense unreal pak parser
- doesn't force files to be extracted
- only converts entries to bytes when requested
- supports up to frozen index (4.25) paks (planned support for higher)
- supports compressed and encrypted paks
- supports iteration over entries
## [click for example code](https://github.com/bananaturtlesandwich/unpak/blob/master/examples/unpak.rs)
## the problem
looking at the libraries for pak reading, they were never not quite right for what i wanted to do:
- [rust-u4pak](https://github.com/panzi/rust-u4pak) - excellent support but very limited api
- [ue4pak](https://github.com/Speedy37/ue4pak-rs) - excellent api but no support for extraction
- [unrealpak](https://github.com/AstroTechies/unrealmodding/tree/main/unreal_pak) - excellent api but only supports version 8
- [rust-unreal-unpak](https://crates.io/crates/rust-unreal-unpak) - is async only supports version 10

so i just though *fuck it i'll do it myself* and did it myself

## references
although the api of [rust-u4pak](https://github.com/panzi/rust-u4pak) wasn't very friendly, the [`README`](https://github.com/panzi/rust-u4pak#readme) went into beautiful detail into the intricacies of the file format and when the readme had incorrect info *cough cough* `encryption uuid` *cough cough* the source code also had the answers as long as you looked hard enough