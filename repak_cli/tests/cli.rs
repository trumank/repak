use assert_cmd::prelude::*;
use indoc::{formatdoc, indoc};
use std::process::Command;

const PAK: &str = "../repak/tests/packs/pack_v11.pak";

#[test]
fn test_cli_info() {
    let assert = Command::cargo_bin("repak")
        .unwrap()
        .arg("info")
        .arg(PAK)
        .assert();
    assert.success().stdout(indoc! {"
        mount point: ../mount/point/root/
        version: V11
        version major: Fnv64BugFix
        encrypted index: false
        encrytion guid: Some(00000000000000000000000000000000)
        path hash seed: Some(205C5A7D)
        4 file entries
    "});
}

#[test]
fn test_cli_list() {
    let assert = Command::cargo_bin("repak")
        .unwrap()
        .arg("list")
        .arg("-s")
        .arg("")
        .arg(PAK)
        .assert();
    assert.success().stdout(indoc! {r#"
        ../mount/point/root/directory/nested.txt
        ../mount/point/root/test.png
        ../mount/point/root/test.txt
        ../mount/point/root/zeros.bin
    "#});

    let assert = Command::cargo_bin("repak")
        .unwrap()
        .arg("list")
        .arg("-s")
        .arg("../mount")
        .arg(PAK)
        .assert();
    assert.success().stdout(indoc! {r#"
        point/root/directory/nested.txt
        point/root/test.png
        point/root/test.txt
        point/root/zeros.bin
    "#});

    let assert = Command::cargo_bin("repak")
        .unwrap()
        .arg("list")
        .arg("-s")
        .arg("../mount/root/asdf")
        .arg(PAK)
        .assert();
    assert.failure().stderr(indoc! {r#"
        Error: Prefix "../mount/root/asdf" does not match path "../mount/point/root/directory/nested.txt"
    "#});
}

#[test]
fn test_cli_get() {
    let assert = Command::cargo_bin("repak")
        .unwrap()
        .arg("get")
        .arg("-s")
        .arg("../mount/point")
        .arg(PAK)
        .arg("root/test.txt")
        .assert();
    assert.success().stdout(indoc! {r#"
        Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
    "#});

    let assert = Command::cargo_bin("repak")
        .unwrap()
        .arg("get")
        .arg("-s")
        .arg("../mount/point")
        .arg(PAK)
        .arg("root/doesnotexist.txt")
        .assert();
    assert.failure().stderr(indoc! {r#"
        Error: No entry found at doesnotexist.txt
    "#});
}

#[test]
fn test_cli_pack() {
    let dir = tempfile::tempdir().unwrap();

    let out_pak = dir.path().join("output.pak");
    let out_dir = dir.path().join("output");

    let assert = Command::cargo_bin("repak")
        .unwrap()
        .arg("pack")
        .arg("../repak/tests/pack/")
        .arg("-m")
        .arg("../mount/point/root")
        .arg("--version")
        .arg("V11")
        .arg(&out_pak)
        .assert();
    assert.success().stdout(formatdoc! {r#"
        Packed 4 files to {}
    "#, out_pak.to_string_lossy()});

    // TODO test packing to non-empty file

    let assert = Command::cargo_bin("repak")
        .unwrap()
        .arg("unpack")
        .arg(&out_pak)
        .arg("-s")
        .arg("../mount/point/root")
        .assert();
    assert.success().stdout(formatdoc! {r#"
        Unpacked 4 files to {} from {}
    "#, out_dir.to_string_lossy(), out_pak.to_string_lossy()});
    assert!(!dir_diff::is_different("../repak/tests/pack/", out_dir).unwrap());
}

#[test]
fn test_cli_unpack() {
    let dir = tempfile::tempdir().unwrap();

    let assert = Command::cargo_bin("repak")
        .unwrap()
        .arg("unpack")
        .arg(PAK)
        .arg("-s")
        .arg("../mount")
        .arg("-o")
        .arg(dir.path())
        .assert();
    assert.success().stdout(formatdoc! {r#"
        Unpacked 4 files to {} from ../repak/tests/packs/pack_v11.pak
    "#, &dir.path().to_string_lossy()});
    assert!(!dir_diff::is_different("../repak/tests/pack/", dir.path().join("point")).unwrap());

    // TODO test unpacking to non-empty directory
}

#[test]
fn test_cli_unpack_include() {
    let dir = tempfile::tempdir().unwrap();

    let assert = Command::cargo_bin("repak")
        .unwrap()
        .arg("unpack")
        .arg(PAK)
        .arg("-s")
        .arg("../mount")
        .arg("-i")
        .arg("point/**/*.txt")
        .arg("-o")
        .arg(dir.path())
        .assert();
    assert.success().stdout(formatdoc! {r#"
        Unpacked 2 files to {} from ../repak/tests/packs/pack_v11.pak
    "#, &dir.path().to_string_lossy()});
}

#[test]
fn test_cli_hashlist() {
    let assert = Command::cargo_bin("repak")
        .unwrap()
        .arg("hash-list")
        .arg(PAK)
        .arg("-s")
        .arg("../mount")
        .assert();
    assert.success().stdout(formatdoc! {r#"
        246c88de650fb20d63abaeb7c1bd8556d0ea260bf4579beafe0b2597e00270a5 point/root/directory/nested.txt
        d7d3e1c21a5b98621add61a4244a413abf5ad6413b0d25ba09bfd5536c75e3b1 point/root/test.png
        56293a80e0394d252e995f2debccea8223e4b5b2b150bee212729b3b39ac4d46 point/root/test.txt
        e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad point/root/zeros.bin
    "#});
}
