use std::collections::BTreeMap;
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
}

#[derive(Parser, Debug)]
struct ActionList {
    /// Input .pak path
    #[arg(index = 1)]
    input: String,

    /// Prefix to strip from entry path
    #[arg(short, long, default_value = "../../../")]
    strip_prefix: String,
}

#[derive(Parser, Debug)]
struct ActionHashList {
    /// Input .pak path
    #[arg(index = 1)]
    input: String,

    /// Prefix to strip from entry path
    #[arg(short, long, default_value = "../../../")]
    strip_prefix: String,
}

#[derive(Parser, Debug)]
struct ActionUnpack {
    /// Input .pak path
    #[arg(index = 1)]
    input: Vec<String>,

    /// Output directory. Defaults to next to input pak
    #[arg(short, long)]
    output: Option<String>,

    /// Prefix to strip from entry path
    #[arg(short, long, default_value = "../../../")]
    strip_prefix: String,

    /// Verbose
    #[arg(short, long, default_value = "false")]
    verbose: bool,

    /// Hides normal output such as progress bar and completion status
    #[arg(short, long, default_value = "false")]
    quiet: bool,

    /// Force overwrite existing files/directories.
    #[arg(short, long, default_value = "false")]
    force: bool,

    /// Files or directories to include. Can be specified multiple times. If not specified, everything is extracted.
    #[arg(action = clap::ArgAction::Append, short, long)]
    include: Vec<glob::Pattern>,
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

    /// Compression
    #[arg(
        long,
        value_parser = clap::builder::PossibleValuesParser::new(repak::Compression::VARIANTS).map(|s| s.parse::<repak::Compression>().unwrap())
    )]
    compression: Option<repak::Compression>,

    /// Path hash seed for >= V10
    #[arg(short, long, default_value = "0")]
    path_hash_seed: u64,

    /// Verbose
    #[arg(short, long, default_value = "false")]
    verbose: bool,

    /// Hides normal output such as progress bar and completion status
    #[arg(short, long, default_value = "false")]
    quiet: bool,

    /// Exclude a directory or pattern from packing, can be specified multiple times. No file is excluded if unspecified
    #[arg(action = clap::ArgAction::Append, short, long)]
    exclude: Vec<glob::Pattern>,
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
}

#[derive(Subcommand, Debug)]
enum Action {
    /// Print .pak info
    Info(ActionInfo),
    /// List .pak files
    List(ActionList),
    /// List .pak files and the SHA256 of their contents. Useful for finding differences between paks
    HashList(ActionHashList),
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
    /// 256 bit AES encryption key as base64 or hex string if the pak is encrypted
    #[arg(short, long)]
    aes_key: Option<AesKey>,

    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, Clone)]
struct AesKey(aes::Aes256);
impl std::str::FromStr for AesKey {
    type Err = repak::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use aes::cipher::KeyInit;
        use base64::{engine::general_purpose, Engine as _};
        let try_parse = |bytes: Vec<_>| aes::Aes256::new_from_slice(&bytes).ok().map(AesKey);
        hex::decode(s.strip_prefix("0x").unwrap_or(s))
            .ok()
            .and_then(try_parse)
            .or_else(|| {
                general_purpose::STANDARD_NO_PAD
                    .decode(s.trim_end_matches('='))
                    .ok()
                    .and_then(try_parse)
            })
            .ok_or(repak::Error::Aes)
    }
}

fn main() -> Result<(), repak::Error> {
    let args = Args::parse();
    let aes_key = args.aes_key.map(|k| k.0);

    match args.action {
        Action::Info(action) => info(aes_key, action),
        Action::List(action) => list(aes_key, action),
        Action::HashList(action) => hash_list(aes_key, action),
        Action::Unpack(action) => unpack(aes_key, action),
        Action::Pack(action) => pack(action),
        Action::Get(action) => get(aes_key, action),
    }
}

fn info(aes_key: Option<aes::Aes256>, action: ActionInfo) -> Result<(), repak::Error> {
    let mut builder = repak::PakBuilder::new();
    if let Some(aes_key) = aes_key {
        builder = builder.key(aes_key);
    }
    let pak = builder.reader(&mut BufReader::new(File::open(action.input)?))?;
    println!("mount point: {}", pak.mount_point());
    println!("version: {}", pak.version());
    println!("version major: {}", pak.version().version_major());
    println!("encrypted index: {}", pak.encrypted_index());
    println!("encrytion guid: {:032X?}", pak.encryption_guid());
    println!("path hash seed: {:08X?}", pak.path_hash_seed());
    println!("{} file entries", pak.files().len());
    Ok(())
}

fn list(aes_key: Option<aes::Aes256>, action: ActionList) -> Result<(), repak::Error> {
    let mut builder = repak::PakBuilder::new();
    if let Some(aes_key) = aes_key {
        builder = builder.key(aes_key);
    }
    let pak = builder.reader(&mut BufReader::new(File::open(action.input)?))?;

    let mount_point = PathBuf::from(pak.mount_point());
    let prefix = Path::new(&action.strip_prefix);

    let full_paths = pak
        .files()
        .into_iter()
        .map(|f| mount_point.join(f))
        .collect::<Vec<_>>();
    let stripped = full_paths
        .iter()
        .map(|f| {
            f.strip_prefix(prefix)
                .map_err(|_| repak::Error::PrefixMismatch {
                    path: f.to_string_lossy().to_string(),
                    prefix: prefix.to_string_lossy().to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    for f in stripped {
        println!("{}", f.to_slash_lossy());
    }

    Ok(())
}

fn hash_list(aes_key: Option<aes::Aes256>, action: ActionHashList) -> Result<(), repak::Error> {
    let mut builder = repak::PakBuilder::new();
    if let Some(aes_key) = aes_key {
        builder = builder.key(aes_key);
    }
    let pak = builder.reader(&mut BufReader::new(File::open(&action.input)?))?;

    let mount_point = PathBuf::from(pak.mount_point());
    let prefix = Path::new(&action.strip_prefix);

    let full_paths = pak
        .files()
        .into_iter()
        .map(|f| (mount_point.join(&f), f))
        .collect::<Vec<_>>();
    let stripped = full_paths
        .iter()
        .map(|(full_path, _path)| {
            full_path
                .strip_prefix(prefix)
                .map_err(|_| repak::Error::PrefixMismatch {
                    path: full_path.to_string_lossy().to_string(),
                    prefix: prefix.to_string_lossy().to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let hashes: std::sync::Arc<std::sync::Mutex<BTreeMap<std::borrow::Cow<'_, str>, Vec<u8>>>> =
        Default::default();
    full_paths.par_iter().zip(stripped).try_for_each_init(
        || (hashes.clone(), File::open(&action.input)),
        |(hashes, file), ((_full_path, path), stripped)| -> Result<(), repak::Error> {
            use sha2::Digest;

            let mut hasher = sha2::Sha256::new();
            pak.read_file(
                path,
                &mut BufReader::new(file.as_ref().unwrap()),
                &mut hasher,
            )?;
            let hash = hasher.finalize();
            hashes
                .lock()
                .unwrap()
                .insert(stripped.to_slash_lossy(), hash.to_vec());
            Ok(())
        },
    )?;

    for (file, hash) in hashes.lock().unwrap().iter() {
        println!("{} {}", hex::encode(hash), file);
    }

    Ok(())
}

const STYLE: &str = "[{elapsed_precise}] [{wide_bar}] {pos}/{len} ({eta})";

#[derive(Clone)]
enum Output {
    Progress(indicatif::ProgressBar),
    Stdout,
}
impl Output {
    pub fn println<I: AsRef<str>>(&self, msg: I) {
        match self {
            Output::Progress(progress) => progress.println(msg),
            Output::Stdout => println!("{}", msg.as_ref()),
        }
    }
}

fn unpack(aes_key: Option<aes::Aes256>, action: ActionUnpack) -> Result<(), repak::Error> {
    for input in &action.input {
        let mut builder = repak::PakBuilder::new();
        if let Some(aes_key) = aes_key.clone() {
            builder = builder.key(aes_key);
        }
        let pak = builder.reader(&mut BufReader::new(File::open(input)?))?;
        let output = action
            .output
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(input).with_extension(""));
        match fs::create_dir(&output) {
            Ok(_) => Ok(()),
            Err(ref e)
                if action.output.is_some() && e.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }?;
        if action.output.is_none() && !action.force && output.read_dir()?.next().is_some() {
            return Err(repak::Error::OutputNotEmpty(
                output.to_string_lossy().to_string(),
            ));
        }
        let mount_point = PathBuf::from(pak.mount_point());
        let prefix = Path::new(&action.strip_prefix);

        struct UnpackEntry {
            entry_path: String,
            out_path: PathBuf,
            out_dir: PathBuf,
        }

        let entries = pak
            .files()
            .into_iter()
            .map(|entry_path| {
                let full_path = mount_point.join(&entry_path);
                if !action.include.is_empty() {
                    if let Ok(stripped) = full_path.strip_prefix(prefix) {
                        let options = glob::MatchOptions {
                            case_sensitive: true,
                            require_literal_separator: true,
                            require_literal_leading_dot: false,
                        };
                        if !action.include.iter().any(|i| {
                            // check full file path
                            i.matches_path_with(stripped, options)
                                // check ancestor directories
                                || stripped.ancestors().skip(1).any(|a| {
                                    i.matches_path_with(a, options)
                                        // hack to check ancestor directories with trailing slash
                                        || i.matches_path_with(&a.join(""), options)
                                })
                        }) {
                            return Ok(None);
                        }
                    } else {
                        return Ok(None);
                    }
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

        let progress = (!action.quiet).then(|| {
            indicatif::ProgressBar::new(entries.len() as u64)
                .with_style(indicatif::ProgressStyle::with_template(STYLE).unwrap())
        });
        let log = match &progress {
            Some(progress) => Output::Progress(progress.clone()),
            None => Output::Stdout,
        };

        entries.par_iter().try_for_each_init(
            || (progress.clone(), File::open(input)),
            |(progress, file), entry| -> Result<(), repak::Error> {
                if action.verbose {
                    log.println(format!("unpacking {}", entry.entry_path));
                }
                fs::create_dir_all(&entry.out_dir)?;
                pak.read_file(
                    &entry.entry_path,
                    &mut BufReader::new(
                        file.as_ref()
                            .map_err(|e| repak::Error::Other(format!("error reading pak: {e}")))?,
                    ),
                    &mut fs::File::create(&entry.out_path)?,
                )?;
                if let Some(progress) = progress {
                    progress.inc(1);
                }
                Ok(())
            },
        )?;
        if let Some(progress) = progress {
            progress.finish();
        }

        if !action.quiet {
            println!(
                "Unpacked {} files to {} from {}",
                entries.len(),
                output.display(),
                input
            );
        }
    }

    Ok(())
}

fn pack(args: ActionPack) -> Result<(), repak::Error> {
    let output = args.output.map(PathBuf::from).unwrap_or_else(|| {
        // NOTE: don't use `with_extension` here because it will replace e.g. the `.1` in
        // `test_v1.1`.
        PathBuf::from(format!("{}.pak", args.input))
    });

    fn collect_files(paths: &mut Vec<PathBuf>, dir: &Path,exclude: &Vec<glob::Pattern>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                collect_files(paths, &path,&exclude)?;
            } else {
                let options = glob::MatchOptions {
                    case_sensitive: true,
                    require_literal_separator: true,
                    require_literal_leading_dot: false,
                };

                let match_path = &entry.path().iter().skip(1).collect::<PathBuf>();
                if exclude.iter().any(|i| {
                    // check full file path
                    i.matches_path_with(&match_path, options)
                        // check ancestor directories
                        || match_path.ancestors().skip(1).any(|a| {
                            i.matches_path_with(a, options)
                                // hack to check ancestor directories with trailing slash
                                || i.matches_path_with(&a.join(""), options)
                        })
                }) {
                    continue;
                }
                else {
                    paths.push(entry.path());
                }
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
    collect_files(&mut paths, input_path,&args.exclude)?;
    paths.sort();

    let mut pak = repak::PakBuilder::new()
        .compression(args.compression.iter().cloned())
        .writer(
            BufWriter::new(File::create(&output)?),
            args.version,
            args.mount_point,
            Some(args.path_hash_seed),
        );

    use indicatif::ProgressIterator;

    let iter = paths.iter();
    let (log, iter) = if !args.quiet {
        let iter =
            iter.progress_with_style(indicatif::ProgressStyle::with_template(STYLE).unwrap());
        (
            Output::Progress(iter.progress.clone()),
            itertools::Either::Left(iter),
        )
    } else {
        (Output::Stdout, itertools::Either::Right(iter))
    };
    let log = log.clone();

    let mut result = None;
    let result_ref = &mut result;
    rayon::in_place_scope(|scope| -> Result<(), repak::Error> {
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        let entry_builder = pak.entry_builder();

        scope.spawn(move |_| {
            *result_ref = Some(
                iter.par_bridge()
                    .try_for_each(|p| -> Result<(), repak::Error> {
                        let rel = &p
                            .strip_prefix(input_path)
                            .expect("file not in input directory")
                            .to_slash()
                            .expect("failed to convert to slash path");
                        if args.verbose {
                            log.println(format!("packing {}", &rel));
                        }
                        let entry = entry_builder.build_entry(true, std::fs::read(p)?)?;

                        tx.send((rel.to_string(), entry)).unwrap();
                        Ok(())
                    }),
            );
        });

        for (path, entry) in rx {
            pak.write_entry(path, entry)?;
        }
        Ok(())
    })?;
    result.unwrap()?;

    pak.write_index()?;

    if !args.quiet {
        println!("Packed {} files to {}", paths.len(), output.display());
    }

    Ok(())
}

fn get(aes_key: Option<aes::Aes256>, args: ActionGet) -> Result<(), repak::Error> {
    let mut reader = BufReader::new(File::open(&args.input)?);
    let mut builder = repak::PakBuilder::new();
    if let Some(aes_key) = aes_key {
        builder = builder.key(aes_key);
    }
    let pak = builder.reader(&mut reader)?;
    let mount_point = PathBuf::from(pak.mount_point());
    let prefix = Path::new(&args.strip_prefix);

    let full_path = prefix.join(args.file);
    let file = full_path
        .strip_prefix(&mount_point)
        .map_err(|_| repak::Error::PrefixMismatch {
            path: full_path.to_string_lossy().to_string(),
            prefix: mount_point.to_string_lossy().to_string(),
        })?;

    use std::io::Write;
    std::io::stdout().write_all(&pak.get(&file.to_slash_lossy(), &mut reader)?)?;
    Ok(())
}
