//! Reader and writer for legacy RAR 1.3/1.4 archives.
//!
//! This crate focuses on the old `RE~^` archive family that predates the
//! later `Rar!\x1a\x07\x00` marker used by RAR 1.5 and newer.

pub mod detect;
pub mod error;
pub mod features;
pub mod rar13;
pub mod version;

mod codec;
mod crypto;

pub use detect::{detect_archive_family, find_archive_start, ArchiveSignature};
pub use error::{Error, Result};
pub use features::FeatureSet;
pub use rar13::{Archive, ExtractedEntry, ExtractedEntryMeta};
pub use version::{ArchiveFamily, ArchiveVersion};
