use crate::version::ArchiveVersion;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooShort,
    UnsupportedSignature,
    InvalidHeader(&'static str),
    UnsupportedVersion(ArchiveVersion),
    UnsupportedFeature {
        version: ArchiveVersion,
        feature: &'static str,
    },
    Io(String),
    NeedPassword,
    CrcMismatch {
        expected: u16,
        actual: u16,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "input is too short"),
            Self::UnsupportedSignature => write!(f, "unsupported archive signature"),
            Self::InvalidHeader(msg) => write!(f, "invalid header: {msg}"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported version: {version:?}"),
            Self::UnsupportedFeature { version, feature } => {
                write!(f, "feature {feature} is not supported by {version:?}")
            }
            Self::Io(message) => write!(f, "I/O error: {message}"),
            Self::NeedPassword => write!(f, "a password is required"),
            Self::CrcMismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected:#06x}, got {actual:#06x}"
                )
            }
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl std::error::Error for Error {}

impl From<crate::codec::Error> for Error {
    fn from(error: crate::codec::Error) -> Self {
        match error {
            crate::codec::Error::InvalidData(message) => Self::InvalidHeader(message),
            crate::codec::Error::NeedMoreInput => Self::InvalidHeader("codec input is truncated"),
        }
    }
}
