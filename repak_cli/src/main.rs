use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};

use clap::builder::TypedValueParser;
use clap::{Parser, Subcommand};
use path_clean::PathClean;
use path_slash::PathExt;
use rayon::prelude::*;
use strum::VariantNames;

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

    /// Force overwrite existing files/directories.
    #[arg(short, long, default_value = "false")]
    force: bool,

    /// Files or directories to include. Can be specified multiple times. If not specified, everything is extracted.
    #[arg(action = clap::ArgAction::Append, short, long)]
    include: Vec<String>,
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

    /// Version
    #[arg(
        long,
        default_value_t = repak::Version::V8B,
        value_parser = clap::builder::PossibleValuesParser::new(repak::Version::VARIANTS).map(|s| s.parse::<repak::Version>().unwrap())
    )]
    version: repak::Version,

    /// Path hash seed for >= V10
    #[arg(short, long, default_value = "0")]
    path_hash_seed: u64,

    /// Verbose
    #[arg(short, long, default_value = "false")]
    verbose: bool,
}

#[derive(Parser, Debug)]
struct ActionGet {
    /// Input .pak path
    #[arg(index = 1)]
    input: String,

    /// Path to file to read to stdout
    #[arg(index = 2)]
    file: String,

    /// Prefix to strip from entry path
    #[arg(short, long, default_value = "../../../")]
    strip_prefix: String,

    /// Base64 encoded AES encryption key if the pak is encrypted
    #[arg(short, long)]
    aes_key: Option<String>,
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
    /// Reads a single file to stdout
    Get(ActionGet),
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
        Action::Get(args) => get(args),
    }
}

fn aes_key(key: &str) -> Result<aes::Aes256, repak::Error> {
    use aes::cipher::KeyInit;
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD
        .decode(key)
        .as_ref()
        .map_err(|_| repak::Error::Base64)
        .and_then(|bytes| aes::Aes256::new_from_slice(bytes).map_err(|_| repak::Error::Aes))
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

const STYLE: &str = "[{elapsed_precise}] [{wide_bar}] {pos}/{len} ({eta})";

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
    if !args.force && output.read_dir()?.next().is_some() {
        return Err(repak::Error::OutputNotEmpty(
            output.to_string_lossy().to_string(),
        ));
    }
    let mount_point = PathBuf::from(pak.mount_point());
    let prefix = Path::new(&args.strip_prefix);

    let includes = args
        .include
        .iter()
        .map(|i| prefix.join(Path::new(i)))
        .collect::<Vec<_>>();

    struct UnpackEntry {
        entry_path: String,
        out_path: PathBuf,
        out_dir: PathBuf,
    }

    let entries =
        pak.files()
            .into_iter()
            .map(|entry_path| {
                let full_path = mount_point.join(&entry_path);
                if !includes.is_empty() && !includes.iter().any(|i| full_path.starts_with(i)) {
                    return Ok(None);
                }
                let out_path = output
                    .join(full_path.strip_prefix(prefix).map_err(|_| {
                        repak::Error::PrefixMismatch {
                            path: full_path.to_string_lossy().to_string(),
                            prefix: prefix.to_string_lossy().to_string(),
                        }
                    })?)
                    .clean();

                if !out_path.starts_with(&output) {
                    return Err(repak::Error::WriteOutsideOutput(
                        out_path.to_string_lossy().to_string(),
                    ));
                }

                let out_dir = out_path.parent().expect("will be a file").to_path_buf();

                Ok(Some(UnpackEntry {
                    entry_path,
                    out_path,
                    out_dir,
                }))
            })
            .filter_map(|e| e.transpose())
            .collect::<Result<Vec<_>, repak::Error>>()?;

    use indicatif::ParallelProgressIterator;

    let iter = entries
        .par_iter()
        .progress_with_style(indicatif::ProgressStyle::with_template(STYLE).unwrap());
    let progress = iter.progress.clone();
    iter.try_for_each_init(
        || (progress.clone(), File::open(&args.input)),
        |(progress, file), entry| -> Result<(), repak::Error> {
            if args.verbose {
                progress.println(format!("unpacking {}", entry.entry_path));
            }
            fs::create_dir_all(&entry.out_dir)?;
            pak.read_file(
                &entry.entry_path,
                &mut BufReader::new(file.as_ref().unwrap()), // TODO: avoid this unwrap
                &mut fs::File::create(&entry.out_path)?,
            )
        },
    )?;

    println!("Unpacked {} files to {}", entries.len(), output.display());

    Ok(())
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
        return Err(repak::Error::InputNotADirectory(
            input_path.to_string_lossy().to_string(),
        ));
    }
    let mut paths = vec![];
    collect_files(&mut paths, input_path)?;
    paths.sort();

    let mut pak = repak::PakWriter::new(
        BufWriter::new(File::create(&output)?),
        None,
        args.version,
        args.mount_point,
        Some(args.path_hash_seed),
    );

    use indicatif::ProgressIterator;

    let mut iter = paths
        .iter()
        .progress_with_style(indicatif::ProgressStyle::with_template(STYLE).unwrap());
    let progress = iter.progress.clone();
    iter.try_for_each(|p| {
        let rel = &p
            .strip_prefix(input_path)
            .expect("file not in input directory")
            .to_slash()
            .expect("failed to convert to slash path");
        if args.verbose {
            progress.println(format!("packing {}", &rel));
        }
        pak.write_file(rel, &mut BufReader::new(File::open(p)?))
    })?;

    pak.write_index()?;

    println!("Packed {} files to {}", paths.len(), output.display());

    Ok(())
}

fn get(args: ActionGet) -> Result<(), repak::Error> {
    let mut reader = BufReader::new(File::open(&args.input)?);
    let pak = repak::PakReader::new_any(
        &mut reader,
        args.aes_key.map(|k| aes_key(k.as_str())).transpose()?,
    )?;
    let mount_point = PathBuf::from(pak.mount_point());
    let prefix = Path::new(&args.strip_prefix);

    let full_path = mount_point.join(args.file);
    let file = full_path
        .strip_prefix(prefix)
        .map_err(|_| repak::Error::PrefixMismatch {
            path: full_path.to_string_lossy().to_string(),
            prefix: prefix.to_string_lossy().to_string(),
        })?;

    use std::io::Write;
    std::io::stdout().write_all(&pak.get(&file.to_string_lossy(), &mut reader)?)?;
    Ok(())
}
