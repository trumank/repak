mod subcommands;

fn main() {
    let mut args = std::env::args();
    args.next();
    let Some(path) = args.next() else {
        help()
    };
    // can't map key to &[u8] because refers to owned data
    match match args.next().unwrap_or_default().as_str() {
        "version" => subcommands::version(path, args.next().unwrap_or_default()),
        "list" => subcommands::list(path, args.next().unwrap_or_default()),
        "unpack" | "" => subcommands::unpack(path, args.next().unwrap_or_default()),
        "help" | _ => help(),
    } {
        Ok(_) => println!("success!"),
        Err(e) => eprintln!("{e}"),
    }
}

fn help() -> ! {
    println!("{HELP}");
    std::process::exit(0)
}

const HELP: &str = r"
usage:
unpak <file> <subcommand> <optional AES key>
                OR
drag the file onto the executable

subcommands:
help - show this message
unpack - decompress the pak
list - print the files in the pak
version - print the version of the pak
";
