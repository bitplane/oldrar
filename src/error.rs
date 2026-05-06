use crate::version::ArchiveVersion;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooShort,
    UnsupportedSignature,
    InvalidHeader(&'static str),
    AtArchiveOffset {
        offset: usize,
        source: Box<Error>,
    },
    AtEntry {
        name: Vec<u8>,
        operation: &'static str,
        source: Box<Error>,
    },
    UnsupportedVersion(ArchiveVersion),
    UnsupportedFeature {
        version: ArchiveVersion,
        feature: &'static str,
    },
    Io(String),
    NeedPassword,
    WrongPasswordOrCorruptData,
    CrcMismatch {
        expected: u16,
        actual: u16,
    },
    Crc32Mismatch {
        expected: u32,
        actual: u32,
    },
    HashMismatch {
        hash_type: u64,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "input is too short"),
            Self::UnsupportedSignature => write!(f, "unsupported archive signature"),
            Self::InvalidHeader(msg) => write!(f, "invalid header: {msg}"),
            Self::AtArchiveOffset { offset, source } => {
                write!(f, "at archive offset {offset:#x}: {source}")
            }
            Self::AtEntry {
                name,
                operation,
                source,
            } => {
                write!(
                    f,
                    "while {operation} entry '{}': {source}",
                    String::from_utf8_lossy(name)
                )
            }
            Self::UnsupportedVersion(version) => write!(f, "unsupported version: {version:?}"),
            Self::UnsupportedFeature { version, feature } => {
                write!(f, "feature {feature} is not supported by {version:?}")
            }
            Self::Io(message) => write!(f, "I/O error: {message}"),
            Self::NeedPassword => write!(f, "a password is required"),
            Self::WrongPasswordOrCorruptData => {
                write!(f, "wrong password or corrupt encrypted data")
            }
            Self::CrcMismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected:#06x}, got {actual:#06x}"
                )
            }
            Self::Crc32Mismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected:#010x}, got {actual:#010x}"
                )
            }
            Self::HashMismatch { hash_type } => {
                write!(f, "hash mismatch for hash type {hash_type}")
            }
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AtArchiveOffset { source, .. } | Self::AtEntry { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl Error {
    pub fn at_archive_offset(self, offset: usize) -> Self {
        Self::AtArchiveOffset {
            offset,
            source: Box::new(self),
        }
    }

    pub fn at_entry(self, name: Vec<u8>, operation: &'static str) -> Self {
        Self::AtEntry {
            name,
            operation,
            source: Box::new(self),
        }
    }
}

impl From<crate::codec::Error> for Error {
    fn from(error: crate::codec::Error) -> Self {
        match error {
            crate::codec::Error::InvalidData(message) => Self::InvalidHeader(message),
            crate::codec::Error::NeedMoreInput => Self::InvalidHeader("codec input is truncated"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_offset_context_exposes_source_error() {
        let error = Error::InvalidHeader("bad block").at_archive_offset(0x1234);

        assert_eq!(
            error.to_string(),
            "at archive offset 0x1234: invalid header: bad block"
        );
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("invalid header: bad block".to_string())
        );
    }

    #[test]
    fn entry_context_exposes_source_error() {
        let error = Error::Crc32Mismatch {
            expected: 1,
            actual: 2,
        }
        .at_entry(b"hello.txt".to_vec(), "verifying");

        assert_eq!(
            error.to_string(),
            "while verifying entry 'hello.txt': checksum mismatch: expected 0x00000001, got 0x00000002"
        );
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("checksum mismatch: expected 0x00000001, got 0x00000002".to_string())
        );
    }
}
