use oldrar::rar13::{extract_volumes, file_checksum, Archive};
use oldrar::{detect_archive_family, find_archive_start, ArchiveFamily, Error};

const EMPTY: &[u8] = include_bytes!("fixtures/rar13/EMPTY.RAR");
const BIG80K: &[u8] = include_bytes!("fixtures/rar13/BIG80K.RAR");
const MULTIFIL: &[u8] = include_bytes!("fixtures/rar13/MULTIFIL.RAR");
const REPEATB: &[u8] = include_bytes!("fixtures/rar13/REPEATB.RAR");
const WITHDIR: &[u8] = include_bytes!("fixtures/rar13/WITHDIR.RAR");
const COMMENT: &[u8] = include_bytes!("fixtures/rar13/COMMENT.RAR");
const FCOMM: &[u8] = include_bytes!("fixtures/rar13/FCOMM.RAR");
const README_PASSWORD: &[u8] = include_bytes!("fixtures/rar13/README_password=password.rar");
const README_COMPRESSED: &[u8] = include_bytes!("fixtures/rar13/README.RAR");
const README_STORE: &[u8] = include_bytes!("fixtures/rar13/README_store.rar");
const README_EXPECTED: &[u8] = include_bytes!("fixtures/rar13/README");
const CMULTI_EXPECTED: &[u8] = include_bytes!("fixtures/rar13/CMULTI.TXT");
const STOREPWD: &[u8] = include_bytes!("fixtures/rar13/STOREPWD.RAR");
const SFXSRC: &[u8] = include_bytes!("fixtures/rar13/SFXSRC.EXE");
const SOLID: &[u8] = include_bytes!("fixtures/rar13/SOLID.RAR");
const MULTIVOL_RAR: &[u8] = include_bytes!("fixtures/rar13/MULTIVOL.RAR");
const MULTIVOL_R00: &[u8] = include_bytes!("fixtures/rar13/MULTIVOL.R00");
const MULTIVOL_R01: &[u8] = include_bytes!("fixtures/rar13/MULTIVOL.R01");
const MULTIVOL_R02: &[u8] = include_bytes!("fixtures/rar13/MULTIVOL.R02");
const CMULTIV_RAR: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.RAR");
const CMULTIV_R00: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R00");
const CMULTIV_R01: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R01");
const CMULTIV_R02: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R02");
const CMULTIV_R03: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R03");
const CMULTIV_R04: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R04");
const CMULTIV_R05: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R05");
const CMULTIV_R06: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R06");

#[test]
fn detects_real_rar1402_archive() {
    let sig = detect_archive_family(README_STORE).expect("signature");
    assert_eq!(sig.family, ArchiveFamily::Rar13);
    assert_eq!(sig.offset, 0);
    assert_eq!(sig.length, 4);
}

#[test]
fn decodes_real_rar1402_stored_file() {
    let archive = Archive::parse(README_STORE).expect("parse RAR 1.402 archive");
    assert_eq!(archive.main.head_size, 7);
    assert_eq!(archive.main.flags, 0x80);
    assert_eq!(archive.entries.len(), 1);

    let entry = &archive.entries[0];
    assert_eq!(entry.name, b"README");
    assert_eq!(entry.header.pack_size, README_EXPECTED.len() as u32);
    assert_eq!(entry.header.unp_size, README_EXPECTED.len() as u32);
    assert_eq!(entry.header.file_crc, 0xe079);
    assert_eq!(entry.header.head_size, 27);
    assert_eq!(entry.header.file_attr, 0x20);
    assert_eq!(entry.header.flags, 0);
    assert_eq!(entry.header.unp_ver, 2);
    assert_eq!(entry.header.method, 0);
    let decoded = entry.stored_data(&archive, None).expect("stored data");
    assert_eq!(decoded, README_EXPECTED);

    let extracted = archive
        .extract_stored(None)
        .expect("extract stored archive");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"README");
    assert_eq!(extracted[0].data, README_EXPECTED);
    assert!(!extracted[0].is_directory);
}

#[test]
fn real_rar1402_stored_checksum_matches_rolling_sum_rotate() {
    let archive = Archive::parse(README_STORE).expect("parse RAR 1.402 archive");
    let entry = &archive.entries[0];
    let decoded = entry.stored_data(&archive, None).expect("stored data");

    assert_eq!(entry.header.file_crc, 0xe079);
    assert_eq!(file_checksum(&decoded), 0xe079);
    entry
        .verify_checksum(&decoded)
        .expect("RAR 1.3 rolling checksum");
}

#[test]
fn decodes_real_rar1402_compressed_file() {
    let archive = Archive::parse(README_COMPRESSED).expect("parse compressed RAR 1.402 archive");
    assert_eq!(archive.entries.len(), 1);
    let entry = &archive.entries[0];
    assert_eq!(entry.name, b"README");
    assert_eq!(entry.header.pack_size, 1078);
    assert_eq!(entry.header.unp_size, README_EXPECTED.len() as u32);
    assert_eq!(entry.header.file_crc, 0xe079);
    assert_eq!(entry.header.method, 3);
    assert!(!entry.is_stored());

    let extracted = archive.extract(None).expect("extract compressed archive");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"README");
    assert_eq!(extracted[0].data, README_EXPECTED);
    assert_eq!(file_checksum(&extracted[0].data), 0xe079);
}

#[test]
fn decodes_real_rar1402_compressed_window_wrap_file() {
    let archive = Archive::parse(BIG80K).expect("parse BIG80K RAR 1.402 archive");
    let extracted = archive.extract(None).expect("extract BIG80K archive");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"BIG80K.TXT");
    assert_eq!(extracted[0].data.len(), 80 * 1024);
    assert_eq!(
        file_checksum(&extracted[0].data),
        archive.entries[0].header.file_crc
    );
}

#[test]
fn decodes_real_rar1402_repeating_pattern_file() {
    let archive = Archive::parse(REPEATB).expect("parse REPEATB RAR 1.402 archive");
    let extracted = archive.extract(None).expect("extract REPEATB archive");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"REPEATB.BIN");
    assert_eq!(extracted[0].data, expected_repeatb());
}

#[test]
fn decodes_real_rar1402_solid_archive() {
    let archive = Archive::parse(SOLID).expect("parse SOLID RAR 1.402 archive");
    assert_eq!(archive.main.flags, 0x88);
    assert!(archive.main.is_solid());
    assert_eq!(archive.entries.len(), 3);

    let extracted = archive.extract(None).expect("extract solid archive");
    assert_eq!(extracted.len(), 3);
    assert_eq!(extracted[0].name, b"BIG80K.TXT");
    assert_eq!(extracted[0].data.len(), 80 * 1024);
    assert_eq!(
        file_checksum(&extracted[0].data),
        archive.entries[0].header.file_crc
    );
    assert_eq!(extracted[1].name, b"HELLO.TXT");
    assert_eq!(extracted[1].data, b"Hello, RAR 1.402 fixture world.\r\n");
    assert_eq!(extracted[2].name, b"TINY.TXT");
    assert_eq!(extracted[2].data, b"AAAAAAAA\r\n");
}

#[test]
fn parses_empty_stored_file() {
    let archive = Archive::parse(EMPTY).expect("parse empty RAR 1.402 archive");
    assert_eq!(archive.main.flags, 0x80);
    assert_eq!(archive.entries.len(), 1);

    let entry = &archive.entries[0];
    assert_eq!(entry.name, b"EMPTY.BIN");
    assert_eq!(entry.header.pack_size, 0);
    assert_eq!(entry.header.unp_size, 0);
    assert_eq!(entry.header.file_crc, 0);
    assert!(entry.is_stored());
    assert_eq!(entry.stored_data(&archive, None).expect("empty data"), b"");
    entry.verify_checksum(b"").expect("empty checksum");

    let extracted = archive.extract_stored(None).expect("extract empty archive");
    assert_eq!(extracted[0].name, b"EMPTY.BIN");
    assert!(extracted[0].data.is_empty());
}

#[test]
fn parses_multiple_file_headers() {
    let archive = Archive::parse(MULTIFIL).expect("parse multi-file RAR 1.402 archive");
    assert_eq!(archive.entries.len(), 2);

    let first = &archive.entries[0];
    assert_eq!(first.name, b"HELLO.TXT");
    assert_eq!(first.header.pack_size, 33);
    assert_eq!(first.header.unp_size, 33);
    assert_eq!(first.header.file_crc, 0x7a6e);
    assert!(first.is_stored());
    assert_eq!(
        first.stored_data(&archive, None).expect("stored HELLO.TXT"),
        b"Hello, RAR 1.402 fixture world.\r\n"
    );
    first
        .verify_checksum(b"Hello, RAR 1.402 fixture world.\r\n")
        .expect("HELLO.TXT checksum");

    let second = &archive.entries[1];
    assert_eq!(second.name, b"TINY.TXT");
    assert_eq!(second.header.pack_size, 7);
    assert_eq!(second.header.unp_size, 10);
    assert_eq!(second.header.file_crc, 0x0642);
    assert_eq!(second.header.method, 3);
    assert!(!second.is_stored());
    assert!(matches!(
        second.stored_data(&archive, None),
        Err(Error::InvalidHeader("RAR 1.3 entry is not stored"))
    ));

    let extracted = archive.extract(None).expect("extract mixed archive");
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"HELLO.TXT");
    assert_eq!(extracted[0].data, b"Hello, RAR 1.402 fixture world.\r\n");
    assert_eq!(extracted[1].name, b"TINY.TXT");
    assert_eq!(extracted[1].data, b"AAAAAAAA\r\n");
}

#[test]
fn parses_directory_entry_and_following_file() {
    let archive = Archive::parse(WITHDIR).expect("parse directory RAR 1.402 archive");
    assert_eq!(archive.entries.len(), 2);

    let dir = &archive.entries[0];
    assert_eq!(dir.name, b"SUBDIR");
    assert_eq!(dir.header.file_attr, 0x10);
    assert!(dir.is_directory());
    assert_eq!(dir.header.pack_size, 0);
    assert_eq!(dir.header.unp_size, 0);

    let file = &archive.entries[1];
    assert_eq!(file.name, b"SUBDIR\\INNER.TXT");
    assert!(!file.is_directory());
    assert!(file.is_stored());
    assert_eq!(
        file.stored_data(&archive, None).expect("stored inner file"),
        b"Inside subdir.\r\n"
    );
    file.verify_checksum(b"Inside subdir.\r\n")
        .expect("inner file checksum");

    let extracted = archive
        .extract_stored(None)
        .expect("extract directory archive");
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"SUBDIR");
    assert!(extracted[0].is_directory);
    assert!(extracted[0].data.is_empty());
    assert_eq!(extracted[1].name, b"SUBDIR\\INNER.TXT");
    assert_eq!(extracted[1].data, b"Inside subdir.\r\n");
}

#[test]
fn parses_encrypted_compressed_file_metadata() {
    let archive = Archive::parse(README_PASSWORD).expect("parse encrypted RAR 1.402 archive");
    assert_eq!(archive.entries.len(), 1);
    let entry = &archive.entries[0];

    assert_eq!(entry.name, b"README");
    assert_eq!(entry.header.pack_size, 1078);
    assert_eq!(entry.header.unp_size, README_EXPECTED.len() as u32);
    assert_eq!(entry.header.file_crc, 0xe079);
    assert_eq!(entry.header.flags, 0x04);
    assert_eq!(entry.header.method, 3);
    assert!(entry.is_encrypted());
    assert!(!entry.is_stored());
}

#[test]
fn decodes_real_rar1402_encrypted_compressed_file() {
    let archive =
        Archive::parse(README_PASSWORD).expect("parse encrypted compressed RAR 1.402 archive");
    assert!(archive.extract(None).is_err());

    let extracted = archive
        .extract(Some(b"password"))
        .expect("extract encrypted compressed archive");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"README");
    assert_eq!(extracted[0].data, README_EXPECTED);
    assert_eq!(file_checksum(&extracted[0].data), 0xe079);
}

#[test]
fn extract_to_decodes_real_rar1402_encrypted_compressed_file() {
    #[derive(Clone)]
    struct SharedWriter(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

    impl std::io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let archive =
        Archive::parse(README_PASSWORD).expect("parse encrypted compressed RAR 1.402 archive");
    let extracted = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    archive
        .extract_to(Some(b"password"), |meta| {
            assert_eq!(meta.name, b"README");
            Ok(Box::new(SharedWriter(extracted.clone())))
        })
        .expect("stream encrypted compressed archive");

    let extracted = extracted.borrow();
    assert_eq!(&*extracted, README_EXPECTED);
    assert_eq!(file_checksum(&extracted), 0xe079);
}

#[test]
fn rejects_wrong_password_for_encrypted_compressed_file() {
    let archive =
        Archive::parse(README_PASSWORD).expect("parse encrypted compressed RAR 1.402 archive");
    assert!(archive.extract(Some(b"wrong-password")).is_err());
}

#[test]
fn rejects_corrupt_stored_payload_checksum() {
    let mut corrupt = README_STORE.to_vec();
    let last = corrupt.last_mut().expect("non-empty fixture");
    *last ^= 0x01;

    let archive = Archive::parse(&corrupt).expect("parse corrupt stored archive");
    assert!(matches!(
        archive.extract(None),
        Err(Error::CrcMismatch { .. })
    ));
}

#[test]
fn rejects_truncated_compressed_payload() {
    let truncated = &README_COMPRESSED[..README_COMPRESSED.len() - 1];
    let err = Archive::parse(truncated).expect_err("truncated archive must not parse");
    assert_eq!(err, Error::TooShort);
}

#[test]
fn decodes_real_rar1402_encrypted_stored_file() {
    let archive = Archive::parse(STOREPWD).expect("parse encrypted stored RAR 1.402 archive");
    assert_eq!(archive.entries.len(), 1);
    let entry = &archive.entries[0];

    assert_eq!(entry.name, b"SECRET.TXT");
    assert_eq!(entry.header.pack_size, 27);
    assert_eq!(entry.header.unp_size, 27);
    assert_eq!(entry.header.file_crc, 0x4423);
    assert_eq!(entry.header.flags, 0x04);
    assert_eq!(entry.header.method, 0);
    assert!(entry.is_encrypted());
    assert!(entry.is_stored());
    assert!(matches!(
        entry.stored_data(&archive, None),
        Err(Error::NeedPassword)
    ));

    let decoded = entry
        .stored_data(&archive, Some(b"password"))
        .expect("decrypt stored data");
    assert_eq!(decoded, b"Stored encrypted fixture.\r\n");
    entry
        .verify_checksum(&decoded)
        .expect("encrypted stored checksum");

    let extracted = archive
        .extract_stored(Some(b"password"))
        .expect("extract encrypted stored archive");
    assert_eq!(extracted[0].name, b"SECRET.TXT");
    assert_eq!(extracted[0].data, b"Stored encrypted fixture.\r\n");
}

#[test]
fn detects_and_parses_rar14_sfx_archive() {
    let sig = find_archive_start(SFXSRC, 128 * 1024).expect("SFX embedded signature");
    assert_eq!(sig.family, ArchiveFamily::Rar13);
    assert_eq!(sig.offset, 6491);

    let archive = Archive::parse(SFXSRC).expect("parse RAR 1.402 SFX archive");
    assert_eq!(archive.sfx_offset, 6491);
    assert_eq!(archive.entries.len(), 1);
    let entry = &archive.entries[0];
    assert_eq!(entry.name, b"HELLO.TXT");
    assert!(entry.is_stored());
    assert_eq!(
        entry
            .stored_data(&archive, None)
            .expect("stored SFX payload"),
        b"Hello, RAR 1.402 fixture world.\r\n"
    );
}

#[test]
fn parses_old_style_multivolume_parts() {
    let cases = [
        (MULTIVOL_RAR, false, true, 19_962, 0x5ec8),
        (MULTIVOL_R00, true, true, 19_962, 0x5147),
        (MULTIVOL_R01, true, true, 19_962, 0xda0b),
        (MULTIVOL_R02, true, false, 5_650, 0x4649),
    ];

    for (bytes, split_before, split_after, pack_size, file_crc) in cases {
        let archive = Archive::parse(bytes).expect("parse multivolume RAR 1.402 part");
        assert_eq!(archive.main.flags, 0x81);
        assert!(archive.main.is_volume());
        assert_eq!(archive.entries.len(), 1);

        let entry = &archive.entries[0];
        assert_eq!(entry.name, b"RANDOM.BIN");
        assert_eq!(entry.header.pack_size, pack_size);
        assert_eq!(entry.header.unp_size, 65_536);
        assert_eq!(entry.header.file_crc, file_crc);
        assert_eq!(entry.is_split_before(), split_before);
        assert_eq!(entry.is_split_after(), split_after);
        assert!(entry.is_stored());
    }
}

#[test]
fn reassembles_old_style_stored_multivolume_file() {
    let volumes = [
        Archive::parse(MULTIVOL_RAR).expect("parse first volume"),
        Archive::parse(MULTIVOL_R00).expect("parse second volume"),
        Archive::parse(MULTIVOL_R01).expect("parse third volume"),
        Archive::parse(MULTIVOL_R02).expect("parse fourth volume"),
    ];

    let extracted = extract_volumes(&volumes, None).expect("join stored volumes");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"RANDOM.BIN");
    assert_eq!(extracted[0].data.len(), 65_536);
    assert_eq!(file_checksum(&extracted[0].data), 0x4649);
}

#[test]
fn parses_old_style_compressed_multivolume_parts() {
    let cases = [
        (CMULTIV_RAR, false, true, 1_962, 0x8523),
        (CMULTIV_R00, true, true, 1_962, 0x8523),
        (CMULTIV_R01, true, true, 1_962, 0x8523),
        (CMULTIV_R02, true, true, 1_962, 0x8523),
        (CMULTIV_R03, true, true, 1_962, 0x87cd),
        (CMULTIV_R04, true, true, 1_962, 0x87cd),
        (CMULTIV_R05, true, true, 1_962, 0x87cd),
        (CMULTIV_R06, true, false, 533, 0x87cd),
    ];

    for (bytes, split_before, split_after, pack_size, file_crc) in cases {
        let archive = Archive::parse(bytes).expect("parse compressed multivolume RAR 1.402 part");
        assert_eq!(archive.main.flags, 0x81);
        assert!(archive.main.is_volume());
        assert_eq!(archive.entries.len(), 1);

        let entry = &archive.entries[0];
        assert_eq!(entry.name, b"CMULTI.TXT");
        assert_eq!(entry.header.pack_size, pack_size);
        assert_eq!(entry.header.unp_size, 98_304);
        assert_eq!(entry.header.file_crc, file_crc);
        assert_eq!(entry.is_split_before(), split_before);
        assert_eq!(entry.is_split_after(), split_after);
        assert!(!entry.is_stored());
    }
}

#[test]
fn reassembles_old_style_compressed_multivolume_file() {
    let volumes = [
        Archive::parse(CMULTIV_RAR).expect("parse first compressed volume"),
        Archive::parse(CMULTIV_R00).expect("parse second compressed volume"),
        Archive::parse(CMULTIV_R01).expect("parse third compressed volume"),
        Archive::parse(CMULTIV_R02).expect("parse fourth compressed volume"),
        Archive::parse(CMULTIV_R03).expect("parse fifth compressed volume"),
        Archive::parse(CMULTIV_R04).expect("parse sixth compressed volume"),
        Archive::parse(CMULTIV_R05).expect("parse seventh compressed volume"),
        Archive::parse(CMULTIV_R06).expect("parse eighth compressed volume"),
    ];

    let extracted = extract_volumes(&volumes, None).expect("join compressed volumes");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"CMULTI.TXT");
    assert_eq!(extracted[0].data, CMULTI_EXPECTED);
    assert_eq!(file_checksum(&extracted[0].data), 0x87cd);
}

#[test]
fn parses_archive_comment_main_header_extension() {
    let archive = Archive::parse(COMMENT).expect("parse comment RAR 1.402 archive");
    assert_eq!(archive.main.flags, 0x92);
    assert_eq!(archive.main.head_size, 43);
    assert_eq!(archive.main.extra.len(), 36);
    assert!(archive.main.has_archive_comment());
    assert!(archive.main.has_packed_comment());
    assert_eq!(archive.entries.len(), 1);

    let entry = &archive.entries[0];
    assert_eq!(entry.name, b"HELLO.TXT");
    assert!(entry.is_stored());
    assert_eq!(
        entry
            .stored_data(&archive, None)
            .expect("stored commented payload"),
        b"Hello, comment fixture.\r\n"
    );
    entry
        .verify_checksum(b"Hello, comment fixture.\r\n")
        .expect("comment fixture payload checksum");
}

#[test]
fn decodes_packed_archive_comment() {
    let archive = Archive::parse(COMMENT).expect("parse comment RAR 1.402 archive");
    let comment = archive
        .archive_comment()
        .expect("decode RAR 1.402 archive comment")
        .expect("archive comment");
    assert_eq!(comment, b"This is the archive comment.\r\n");
}

#[test]
fn parses_and_decodes_file_comment_header_extension() {
    let archive = Archive::parse(FCOMM).expect("parse file-comment RAR 1.402 archive");
    assert_eq!(archive.entries.len(), 1);

    let entry = &archive.entries[0];
    assert_eq!(entry.name, b"HELLO.TXT");
    assert_eq!(entry.header.flags, 0x08);
    assert_eq!(entry.header.head_size, 38);
    assert_eq!(entry.extra, b"\x06\x00FCOM\r\n");
    assert_eq!(
        entry
            .file_comment()
            .expect("decode file comment")
            .expect("file comment"),
        b"FCOM\r\n"
    );
    assert_eq!(
        entry
            .stored_data(&archive, None)
            .expect("stored file-comment payload"),
        b"Hello, file comment fixture.\r\n"
    );
}

fn expected_repeatb() -> Vec<u8> {
    let mut out = Vec::with_capacity(256 * 32);
    for _ in 0..32 {
        out.extend(0u8..=255);
    }
    out
}
