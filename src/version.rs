#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFamily {
    Rar13,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveVersion {
    Rar13,
    Rar14,
}

impl ArchiveVersion {
    pub const fn family(self) -> ArchiveFamily {
        ArchiveFamily::Rar13
    }

    pub const fn is_rar13_family(self) -> bool {
        matches!(self, Self::Rar13 | Self::Rar14)
    }
}
