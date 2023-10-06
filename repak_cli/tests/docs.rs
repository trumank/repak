fn workspace_dir() -> std::path::PathBuf {
    let output = std::process::Command::new(env!("CARGO"))
        .arg("locate-project")
        .arg("--workspace")
        .arg("--message-format=plain")
        .output()
        .unwrap()
        .stdout;
    let cargo_path = std::path::Path::new(std::str::from_utf8(&output).unwrap().trim());
    cargo_path.parent().unwrap().to_path_buf()
}

#[test]
fn test_readme_help() {
    use assert_cmd::prelude::*;
    use std::process::Command;

    let err = Command::cargo_bin("repak").unwrap().unwrap_err();
    let help = std::str::from_utf8(&err.as_output().unwrap().stderr).unwrap();

    let readme = std::fs::read_to_string(workspace_dir().join("README.md")).unwrap();

    assert!(readme.contains(&format!("```console\n$ repak --help\n{help}```")));
}
