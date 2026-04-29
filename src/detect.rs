use crate::version::ArchiveFamily;

pub const RAR13_SIGNATURE: &[u8; 4] = b"RE~^";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveSignature {
    pub family: ArchiveFamily,
    pub offset: usize,
    pub length: usize,
}

pub fn detect_archive_family(input: &[u8]) -> Option<ArchiveSignature> {
    detect_at(input, 0)
}

pub fn find_archive_start(input: &[u8], max_scan: usize) -> Option<ArchiveSignature> {
    let limit = input.len().min(max_scan);
    (0..=limit).find_map(|offset| detect_at(input, offset))
}

fn detect_at(input: &[u8], offset: usize) -> Option<ArchiveSignature> {
    let tail = input.get(offset..)?;

    if tail.starts_with(RAR13_SIGNATURE) {
        Some(ArchiveSignature {
            family: ArchiveFamily::Rar13,
            offset,
            length: RAR13_SIGNATURE.len(),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_all_known_signatures() {
        assert_eq!(
            detect_archive_family(b"RE~^").unwrap().family,
            ArchiveFamily::Rar13
        );
        assert_eq!(detect_archive_family(b"Rar!\x1a\x07\x00"), None);
        assert_eq!(detect_archive_family(b"Rar!\x1a\x07\x01\x00"), None);
    }

    #[test]
    fn finds_sfx_prefixed_archive() {
        let sig = find_archive_start(b"stub bytes RE~^payload", 128).unwrap();
        assert_eq!(sig.family, ArchiveFamily::Rar13);
        assert_eq!(sig.offset, 11);
    }

    #[test]
    fn rejects_unknown_and_truncated_signatures() {
        assert_eq!(detect_archive_family(b""), None);
        assert_eq!(detect_archive_family(b"RAR!"), None);
        assert_eq!(detect_archive_family(b"Rar!\x1a\x07"), None);
        assert_eq!(find_archive_start(b"not an archive", 128), None);
    }

    #[test]
    fn scan_limit_bounds_sfx_detection() {
        let input = b"stub bytes RE~^payload";

        assert_eq!(find_archive_start(input, 10), None);

        let sig = find_archive_start(input, 11).unwrap();
        assert_eq!(sig.family, ArchiveFamily::Rar13);
        assert_eq!(sig.offset, 11);
        assert_eq!(sig.length, RAR13_SIGNATURE.len());
    }
}
