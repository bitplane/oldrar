# oldrar

`oldrar` is a Rust reader and writer for the legacy RAR 1.3/1.4 archive
family. These archives use the old `RE~^` marker and predate the later
`Rar!\x1a\x07\x00` signature used by RAR 1.5 and newer.

The goal is archivist-oriented compatibility with old archives that are not
handled by many modern tools.

## Current Status

- detects `RE~^` archives, including SFX-prefixed archives;
- parses main/file headers, directory entries, comments, and old-style volume
  flags;
- extracts stored and Unpack15-compressed files;
- supports the historical RAR 1.4 password cipher for file data;
- supports solid archives;
- reassembles stored and compressed old-style multi-volume archives;
- writes valid stored and compressed RAR 1.4 archives, including comments,
  file password encryption, solid mode, and old-style volumes.

Deferred:

- cryptographic AV signature verification;
- AV writing;
- SFX stub generation;
- byte-identical WinRAR compressor heuristics.

## Example

```rust
let bytes = std::fs::read("archive.rar")?;
let archive = oldrar::Archive::parse(&bytes)?;
let entries = archive.extract(None)?;
for entry in entries {
    println!("{}", String::from_utf8_lossy(&entry.name));
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## CLI

The crate also builds an `oldrar` binary:

```sh
oldrar info archive.rar
oldrar test archive.rar
oldrar x archive.rar out-dir
oldrar a archive.rar file1.txt file2.txt
```

Useful options:

```sh
oldrar test --password password archive.rar
oldrar x --password password archive.rar out-dir
oldrar a --store archive.rar file.txt
oldrar a --solid archive.rar file1.txt file2.txt
oldrar a --comment "archive note" --file-comment "file note" archive.rar file.txt
oldrar a --store --volume-size 100000 split.rar file.bin
```
