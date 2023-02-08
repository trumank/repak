use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use path_clean::PathClean;
use rayon::prelude::*;

#[derive(Parser, Debug)]
struct ActionInfo {
    /// Input .pak path
    #[arg(index = 1)]
    input: String,

    /// Base64 encoded AES encryption key if the pak is encrypted
    #[arg(short, long)]
    aes_key: Option<String>,
}

#[derive(Parser, Debug)]
struct ActionList {
    /// Input .pak path
    #[arg(index = 1)]
    input: String,

    /// Base64 encoded AES encryption key if the pak is encrypted
    #[arg(short, long)]
    aes_key: Option<String>,
}

#[derive(Parser, Debug)]
struct ActionUnpack {
    /// Input .pak path
    #[arg(index = 1)]
    input: String,

    /// Output directory. Defaults to next to input pak
    #[arg(index = 2)]
    output: Option<String>,

    /// Prefix to strip from entry path
    #[arg(short, long, default_value = "../../../")]
    strip_prefix: String,

    /// Base64 encoded AES encryption key if the pak is encrypted
    #[arg(short, long)]
    aes_key: Option<String>,

    /// Verbose
    #[arg(short, long, default_value = "false")]
    verbose: bool,
}

#[derive(Parser, Debug)]
struct ActionPack {
    /// Input directory
    #[arg(index = 1)]
    input: String,

    /// Output directory. Defaults to next to input dir
    #[arg(index = 2)]
    output: Option<String>,

    /// Mount point
    #[arg(short, long, default_value = "../../../")]
    mount_point: String,

    /// Verbose
    #[arg(short, long, default_value = "false")]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Action {
    /// Print .pak info
    Info(ActionInfo),
    /// List .pak files
    List(ActionInfo),
    /// Unpack .pak file
    Unpack(ActionUnpack),
    /// Pack directory into .pak file
    Pack(ActionPack),
}

#[derive(Parser, Debug)]
#[command(author, version)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

fn main() -> Result<(), repak::Error> {
    let args = Args::parse();

    match args.action {
        Action::Info(args) => info(args),
        Action::List(args) => list(args),
        Action::Unpack(args) => unpack(args),
        Action::Pack(args) => pack(args),
    }
}

fn aes_key(key: &str) -> Result<aes::Aes256Dec, repak::Error> {
    use aes::cipher::KeyInit;
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD
        .decode(key)
        .as_ref()
        .map_err(|_| repak::Error::Base64)
        .and_then(|bytes| aes::Aes256Dec::new_from_slice(bytes).map_err(|_| repak::Error::Aes))
}

fn info(args: ActionInfo) -> Result<(), repak::Error> {
    let pak = repak::PakReader::new_any(
        BufReader::new(File::open(&args.input)?),
        args.aes_key.map(|k| aes_key(k.as_str())).transpose()?,
    )?;
    println!("mount point: {}", pak.mount_point());
    println!("version: {}", pak.version());
    println!("version major: {}", pak.version().version_major());
    println!("{} file entries", pak.files().len());
    Ok(())
}

fn list(args: ActionInfo) -> Result<(), repak::Error> {
    let pak = repak::PakReader::new_any(
        BufReader::new(File::open(&args.input)?),
        args.aes_key.map(|k| aes_key(k.as_str())).transpose()?,
    )?;
    for f in pak.files() {
        println!("{f}");
    }
    Ok(())
}

fn unpack(args: ActionUnpack) -> Result<(), repak::Error> {
    let pak = repak::PakReader::new_any(
        BufReader::new(File::open(&args.input)?),
        args.aes_key.map(|k| aes_key(k.as_str())).transpose()?,
    )?;
    let output = args
        .output
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(&args.input).with_extension(""));
    match fs::create_dir(&output) {
        Ok(_) => Ok(()),
        Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }?;
    if output.read_dir()?.next().is_some() {
        return Err(repak::Error::Other("output directory not empty"));
    }
    let mount_point = PathBuf::from(pak.mount_point());
    let prefix = Path::new(&args.strip_prefix);
    pak.files().into_par_iter().try_for_each_init(
        || File::open(&args.input),
        |file, path| -> Result<(), repak::Error> {
            if args.verbose {
                println!("extracting {path}");
            }
            let file_path = output.join(
                mount_point
                    .join(&path)
                    .strip_prefix(prefix)
                    .map_err(|_| repak::Error::Other("prefix does not match"))?,
            );
            if !file_path.clean().starts_with(&output) {
                return Err(repak::Error::Other(
                    "tried to write file outside of output directory",
                ));
            }
            fs::create_dir_all(file_path.parent().expect("will be a file"))?;
            pak.read_file(
                &path,
                &mut BufReader::new(file.as_ref().unwrap()), // TODO: avoid this unwrap
                &mut fs::File::create(file_path)?,
            )
        },
    )
}

fn pack(args: ActionPack) -> Result<(), repak::Error> {
    let output = args
        .output
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(&args.input).with_extension("pak"));

    fn collect_files(paths: &mut Vec<PathBuf>, dir: &Path) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                collect_files(paths, &path)?;
            } else {
                paths.push(entry.path());
            }
        }
        Ok(())
    }
    let input_path = Path::new(&args.input);
    if !input_path.is_dir() {
        return Err(repak::Error::Other("input is not a directory"));
    }
    let mut paths = vec![];
    collect_files(&mut paths, input_path)?;
    paths.sort();

    let mut pak = repak::PakWriter::new(
        BufWriter::new(File::create(output)?),
        None,
        repak::Version::V8B,
        args.mount_point,
    );

    for p in paths {
        let rel = &p
            .strip_prefix(input_path)
            .expect("file not in input directory")
            .to_string_lossy();
        if args.verbose {
            println!("packing {}", &rel);
        }
        pak.write_file(rel, &mut BufReader::new(File::open(&p)?))?;
    }

    pak.write_index()?;

    Ok(())
}
