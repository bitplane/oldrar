use oldrar::rar13::{self, FileEntry, StoredEntry, WriterOptions};
use oldrar::{Archive, ArchiveVersion, Error, ExtractedEntryMeta, FeatureSet};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

type CliResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const ADD_USAGE: &str =
    "usage: oldrar a [--store] [--solid] [--password <password>] [--comment <text>] [--file-comment <text>] [--volume-size <bytes>] <archive> <files...>";

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> CliResult<()> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        usage();
        return Ok(());
    };
    let rest: Vec<String> = args.collect();

    match command.as_str() {
        "info" => cmd_info(&rest),
        "test" => cmd_test(&rest),
        "x" => cmd_extract(&rest),
        "a" => cmd_add(&rest),
        "-h" | "--help" | "help" => {
            usage();
            Ok(())
        }
        _ => Err(format!("unknown command: {command}").into()),
    }
}

fn cmd_info(args: &[String]) -> CliResult<()> {
    if args.is_empty() {
        return Err("usage: oldrar info <archive>...".into());
    }

    for path in args {
        let archive = Archive::parse_path(path).map_err(|err| read_archive_error(path, err))?;
        println!("{path}: Rar13 at offset {}", archive.sfx_offset);
        println!(
            "  main: flags={:#04x} head_size={} sfx_offset={}",
            archive.main.flags, archive.main.head_size, archive.sfx_offset
        );
        if archive.main.has_archive_comment() {
            println!(
                "  archive comment extension: {} bytes{}",
                archive.main.extra.len(),
                if archive.main.has_packed_comment() {
                    " (packed)"
                } else {
                    ""
                }
            );
            if let Some(comment) = archive
                .archive_comment()
                .map_err(|err| format!("failed to decode archive comment '{path}': {err}"))?
            {
                println!("  comment: {}", String::from_utf8_lossy(&comment));
            }
        }
        if let Some(av) = archive.authenticity_verification().map_err(|err| {
            format!("failed to parse authenticity verification in '{path}': {err}")
        })? {
            println!(
                "  authenticity verification: structural size={} cipher_body={} status=not-cryptographically-verified",
                av.size,
                av.cipher_body.len()
            );
        }
        for (index, entry) in archive.entries.iter().enumerate() {
            println!(
                "  #{index}: {} pack={} unp={} method={} flags={:#04x} attr={:#04x} checksum={:#06x}",
                entry.name_lossy(),
                entry.header.pack_size,
                entry.header.unp_size,
                entry.header.method,
                entry.header.flags,
                entry.header.file_attr,
                entry.header.file_crc
            );
            if let Some(comment) = entry.file_comment().map_err(|err| {
                format!(
                    "failed to decode file comment '{}' in '{path}': {err}",
                    entry.name_lossy()
                )
            })? {
                println!("    comment: {}", String::from_utf8_lossy(&comment));
            }
        }
    }

    Ok(())
}

fn cmd_test(args: &[String]) -> CliResult<()> {
    let (password, paths) = parse_password(args)?;
    if paths.is_empty() {
        return Err("usage: oldrar test [--password <password>] <archive> [parts...]".into());
    }

    let mut entries = Vec::new();
    if paths.len() == 1 {
        let archive =
            Archive::parse_path(&paths[0]).map_err(|err| read_archive_error(&paths[0], err))?;
        archive
            .extract_to(password.as_deref(), |meta| {
                entries.push(meta.clone());
                Ok(Box::new(std::io::sink()))
            })
            .map_err(|err| format!("failed to test archive '{}': {err}", paths[0]))?;
    } else {
        let archives = parse_archives(&paths)?;
        rar13::extract_volumes_to(&archives, password.as_deref(), |meta| {
            entries.push(meta.clone());
            Ok(Box::new(std::io::sink()))
        })
        .map_err(|err| format!("failed to test volume set '{}': {err}", paths.join(", ")))?;
    }

    for entry in &entries {
        print_ok_entry(entry);
    }
    Ok(())
}

fn cmd_extract(args: &[String]) -> CliResult<()> {
    let (password, mut paths) = parse_password(args)?;
    if paths.len() < 2 {
        return Err("usage: oldrar x [--password <password>] <archive> [parts...] <outdir>".into());
    }
    let out_dir = PathBuf::from(paths.pop().expect("outdir"));

    let mut names = Vec::new();
    if paths.len() == 1 {
        let archive =
            Archive::parse_path(&paths[0]).map_err(|err| read_archive_error(&paths[0], err))?;
        archive
            .extract_to(password.as_deref(), |meta| {
                names.push(meta.name.clone());
                open_output_writer(&out_dir, meta)
            })
            .map_err(|err| {
                format!(
                    "failed to write extracted entry to '{}': {err}",
                    out_dir.display()
                )
            })?;
    } else {
        let archives = parse_archives(&paths)?;
        rar13::extract_volumes_to(&archives, password.as_deref(), |meta| {
            names.push(meta.name.clone());
            open_output_writer(&out_dir, meta)
        })
        .map_err(|err| format!("failed to extract volume set '{}': {err}", paths.join(", ")))?;
    }

    for name in &names {
        println!("x {}", String::from_utf8_lossy(name));
    }
    Ok(())
}

fn cmd_add(args: &[String]) -> CliResult<()> {
    let (password, args) = parse_password(args)?;
    if args.len() < 2 {
        return Err(ADD_USAGE.into());
    }

    let mut store = false;
    let mut solid = false;
    let mut archive_comment = None;
    let mut file_comment = None;
    let mut volume_size = None;
    let mut archive_index = 0;
    while let Some(arg) = args.get(archive_index) {
        match arg.as_str() {
            "--store" => {
                store = true;
                archive_index += 1;
            }
            "--solid" => {
                solid = true;
                archive_index += 1;
            }
            "--comment" => {
                let value = args
                    .get(archive_index + 1)
                    .ok_or("missing --comment value")?;
                archive_comment = Some(value.as_bytes().to_vec());
                archive_index += 2;
            }
            "--file-comment" => {
                let value = args
                    .get(archive_index + 1)
                    .ok_or("missing --file-comment value")?;
                file_comment = Some(value.as_bytes().to_vec());
                archive_index += 2;
            }
            "--volume-size" => {
                let value = args
                    .get(archive_index + 1)
                    .ok_or("missing --volume-size value")?;
                volume_size = Some(value.parse::<usize>()?);
                archive_index += 2;
            }
            unknown if unknown.starts_with('-') => {
                return Err(format!("unknown add option: {unknown}").into());
            }
            _ => break,
        }
    }
    if args.len() <= archive_index {
        return Err(ADD_USAGE.into());
    }
    if solid && store {
        return Err("solid RAR 1.4 output requires compression".into());
    }

    let archive_path = PathBuf::from(&args[archive_index]);
    let input_paths = &args[archive_index + 1..];
    if input_paths.is_empty() {
        return Err("no input files".into());
    }
    if volume_size.is_some() && input_paths.len() != 1 {
        return Err("RAR 1.4 multivolume writer currently supports one input file".into());
    }

    let owned = read_inputs(input_paths, password.as_deref())?;
    let mut features = FeatureSet::store_only();
    features.solid = solid;
    let options = WriterOptions {
        target: ArchiveVersion::Rar14,
        features,
    };

    if let Some(volume_size) = volume_size {
        let entry = owned.first().expect("one input checked above");
        let parts = if store {
            let entry = StoredEntry {
                name: &entry.name,
                data: &entry.data,
                file_time: 0,
                file_attr: entry.file_attr,
                password: entry.password.as_deref(),
                file_comment: file_comment.as_deref(),
            };
            rar13::write_stored_volumes(entry, options, volume_size)?
        } else {
            let entry = FileEntry {
                name: &entry.name,
                data: &entry.data,
                file_time: 0,
                file_attr: entry.file_attr,
                password: entry.password.as_deref(),
                file_comment: file_comment.as_deref(),
            };
            rar13::write_compressed_volumes(entry, options, volume_size)?
        };
        write_volume_parts(&archive_path, &parts).map_err(|err| {
            format!(
                "failed to write volume set starting at '{}': {err}",
                archive_path.display()
            )
        })?;
        println!("created {} volumes", parts.len());
        return Ok(());
    }

    let bytes = if store {
        let entries: Vec<_> = owned
            .iter()
            .map(|entry| StoredEntry {
                name: &entry.name,
                data: &entry.data,
                file_time: 0,
                file_attr: entry.file_attr,
                password: entry.password.as_deref(),
                file_comment: file_comment.as_deref(),
            })
            .collect();
        rar13::write_stored_archive_with_comment(&entries, options, archive_comment.as_deref())?
    } else {
        let entries: Vec<_> = owned
            .iter()
            .map(|entry| FileEntry {
                name: &entry.name,
                data: &entry.data,
                file_time: 0,
                file_attr: entry.file_attr,
                password: entry.password.as_deref(),
                file_comment: file_comment.as_deref(),
            })
            .collect();
        rar13::write_compressed_archive_with_comment(&entries, options, archive_comment.as_deref())?
    };
    fs::write(&archive_path, bytes).map_err(|err| {
        format!(
            "failed to write archive '{}': {err}",
            archive_path.display()
        )
    })?;
    println!("created {}", archive_path.display());
    Ok(())
}

fn write_volume_parts(first_path: &Path, parts: &[Vec<u8>]) -> CliResult<()> {
    for (index, bytes) in parts.iter().enumerate() {
        let path = volume_part_path(first_path, index)?;
        fs::write(path, bytes)?;
    }
    Ok(())
}

fn volume_part_path(first_path: &Path, index: usize) -> CliResult<PathBuf> {
    if index == 0 {
        return Ok(first_path.to_path_buf());
    }
    if index > 100 {
        return Err("RAR 1.4 old-style volume names only support .r00 through .r99 here".into());
    }
    Ok(first_path.with_extension(format!("r{:02}", index - 1)))
}

fn parse_password(args: &[String]) -> CliResult<(Option<Vec<u8>>, Vec<String>)> {
    let mut password = None;
    let mut rest = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--password" || arg == "-p" {
            let value = iter.next().ok_or("missing password value")?;
            password = Some(value.as_bytes().to_vec());
        } else {
            rest.push(arg.clone());
        }
    }
    Ok((password, rest))
}

fn parse_archives(paths: &[String]) -> CliResult<Vec<Archive>> {
    let mut archives = Vec::new();
    for path in paths {
        archives.push(Archive::parse_path(path).map_err(|err| read_archive_error(path, err))?);
    }
    Ok(archives)
}

fn read_archive_error(path: &str, err: Error) -> String {
    match err {
        Error::Io(message) => format!("failed to read archive '{path}': {message}"),
        Error::UnsupportedSignature => {
            format!("failed to identify archive '{path}': unsupported archive signature")
        }
        other => format!("failed to parse archive '{path}': {other}"),
    }
}

fn open_output_writer(
    out_dir: &Path,
    entry: &ExtractedEntryMeta,
) -> oldrar::Result<Box<dyn Write>> {
    let rel = output_relative_path(&entry.name)
        .map_err(|_| Error::InvalidHeader("unsafe archive path"))?;
    let out_path = out_dir.join(rel);
    if entry.is_directory {
        fs::create_dir_all(&out_path)?;
        return Ok(Box::new(std::io::sink()));
    }
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(Box::new(fs::File::create(out_path)?))
}

fn print_ok_entry(entry: &ExtractedEntryMeta) {
    println!(
        "OK {}{}",
        String::from_utf8_lossy(&entry.name),
        if entry.is_directory { "/" } else { "" }
    );
}

fn output_relative_path(name: &[u8]) -> CliResult<PathBuf> {
    let text = String::from_utf8_lossy(name).replace('\\', "/");
    let path = Path::new(&text);
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return Err(format!("unsafe archive path: {text}").into()),
        }
    }
    if out.as_os_str().is_empty() {
        return Err("empty archive path".into());
    }
    Ok(out)
}

struct OwnedInput {
    name: Vec<u8>,
    data: Vec<u8>,
    file_attr: u8,
    password: Option<Vec<u8>>,
}

fn read_inputs(paths: &[String], password: Option<&[u8]>) -> CliResult<Vec<OwnedInput>> {
    let mut out = Vec::new();
    for path in paths {
        let path = Path::new(path);
        let name = path
            .file_name()
            .ok_or("input path has no file name")?
            .to_string_lossy()
            .as_bytes()
            .to_vec();
        let meta = fs::metadata(path)
            .map_err(|err| format!("failed to stat input '{}': {err}", path.display()))?;
        if meta.is_dir() {
            out.push(OwnedInput {
                name,
                data: Vec::new(),
                file_attr: 0x10,
                password: None,
            });
        } else {
            let data = fs::read(path)
                .map_err(|err| format!("failed to read input '{}': {err}", path.display()))?;
            out.push(OwnedInput {
                name,
                data,
                file_attr: 0x20,
                password: password.map(|p| p.to_vec()),
            });
        }
    }
    Ok(out)
}

fn usage() {
    eprintln!(
        "usage:
  oldrar info <archive>...
  oldrar test [--password <password>] <archive> [parts...]
  oldrar x [--password <password>] <archive> [parts...] <outdir>
  {ADD_USAGE}"
    );
}
