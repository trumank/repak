pub fn decompress() -> repak::Decompress {
    *unsafe { OODLE.as_ref().unwrap().get(b"OodleLZ_Decompress") }.unwrap()
}

use once_cell::sync::Lazy;
static OODLE: Lazy<Result<libloading::Library, String>> =
    Lazy::new(|| get_oodle().map_err(|e| e.to_string()));
static OODLE_HASH: [u8; 20] = hex_literal::hex!("4bcc73614cb8fd2b0bce8d0f91ee5f3202d9d624");

fn get_oodle() -> Result<libloading::Library, repak::Error> {
    use sha1::{Digest, Sha1};

    let oodle = std::env::current_exe()?.with_file_name("oo2core_9_win64.dll");
    if !oodle.exists() {
        let mut data = vec![];
        ureq::get("https://cdn.discordapp.com/attachments/817251677086285848/992648087371792404/oo2core_9_win64.dll")
            .call().map_err(|e| repak::Error::Other(e.to_string()))?
            .into_reader().read_to_end(&mut data)?;

        std::fs::write(&oodle, data)?;
    }

    let mut hasher = Sha1::new();
    hasher.update(std::fs::read(&oodle)?);
    let hash = hasher.finalize();
    (hash[..] == OODLE_HASH).then_some(()).ok_or_else(|| {
        repak::Error::Other(format!(
            "oodle hash mismatch expected: {} got: {} ",
            hex::encode(OODLE_HASH),
            hex::encode(hash)
        ))
    })?;

    unsafe { libloading::Library::new(oodle) }.map_err(|_| repak::Error::OodleFailed)
}
