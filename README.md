# oldrar

`oldrar` is a Rust reader and writer for RAR 1.3/1.4 archives from the DOS days.
The goal is archivist-oriented compatibility with old archives that are not
handled by many modern tools. It's not a very good compressor, but it can make
test data.

* [🏠 home](https://bitplane.net/dev/rust/oldrar)
* [🐱 source](https://github.com/bitplane/oldrar)
* [🦀 crate](https://crates.io/crates/oldrar)

## Support

- detects `RE~^` archives, including SFX-prefixed archives;
- parses main/file headers, directory entries, comments, and old-style volume
  flags;
- extracts stored and Unpack15-compressed files;
- supports the historical RAR 1.4 password cipher for file data;
- supports solid archives;
- reassembles stored and compressed old-style multi-volume archives;
- writes valid stored and compressed RAR 1.4 archives, including comments,
  file password encryption, solid mode, and old-style volumes.

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
