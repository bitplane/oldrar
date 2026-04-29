use crate::codec::{unpack15_decode, unpack15_encode, Unpack15, Unpack15Encoder};
use crate::crypto::{Rar13Cipher, Rar13DecryptReader};
use crate::detect::{find_archive_start, RAR13_SIGNATURE};
use crate::error::{Error, Result};
use crate::features::FeatureSet;
use crate::version::{ArchiveFamily, ArchiveVersion};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MAIN_HEAD_SIZE: u16 = 7;
const FILE_HEAD_BASE_SIZE: usize = 21;
const MHD_VOLUME: u8 = 0x01;
const MHD_COMMENT: u8 = 0x02;
const MHD_SOLID: u8 = 0x08;
const MHD_PACK_COMMENT: u8 = 0x10;
const MHD_AV: u8 = 0x20;
const MHD_ALWAYS_SET: u8 = 0x80;
const RAR13_AV_PREFIX: &[u8; 6] = b"\x1ai\x6d\x02\xda\xae";
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const LHD_SPLIT_BEFORE: u8 = 0x01;
const LHD_SPLIT_AFTER: u8 = 0x02;
const LHD_PASSWORD: u8 = 0x04;
const LHD_COMMENT: u8 = 0x08;
const LHD_SOLID: u8 = 0x10;
const METHOD_STORE: u8 = 0;
const DEFAULT_UNP_VER: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainHeader {
    pub flags: u8,
    pub head_size: u16,
    pub extra: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub flags: u8,
    pub pack_size: u32,
    pub unp_size: u32,
    pub file_crc: u16,
    pub file_time: u32,
    pub file_attr: u8,
    pub unp_ver: u8,
    pub method: u8,
    pub head_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub header: FileHeader,
    pub name: Vec<u8>,
    pub extra: Vec<u8>,
    pub packed_range: Range<usize>,
}

#[derive(Debug, Clone)]
pub struct Archive {
    pub sfx_offset: usize,
    pub main: MainHeader,
    pub entries: Vec<Entry>,
    source: ArchiveSource,
}

#[derive(Debug, Clone)]
enum ArchiveSource {
    Memory(Arc<[u8]>),
    File(Arc<PathBuf>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticityVerification {
    pub size: u16,
    pub prefix: [u8; 6],
    pub cipher_body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticityVerificationStatus {
    Absent,
    StructurallyValid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedEntry {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub file_time: u32,
    pub file_attr: u8,
    pub is_directory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedEntryMeta {
    pub name: Vec<u8>,
    pub file_time: u32,
    pub file_attr: u8,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterOptions {
    pub target: ArchiveVersion,
    pub features: FeatureSet,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            target: ArchiveVersion::Rar14,
            features: FeatureSet::store_only(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.flags & MHD_VOLUME != 0
    }

    pub fn has_archive_comment(&self) -> bool {
        self.flags & MHD_COMMENT != 0
    }

    pub fn has_packed_comment(&self) -> bool {
        self.flags & MHD_PACK_COMMENT != 0
    }

    pub fn is_solid(&self) -> bool {
        self.flags & MHD_SOLID != 0
    }

    pub fn has_authenticity_verification(&self) -> bool {
        self.flags & MHD_AV != 0
    }

    fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < MAIN_HEAD_SIZE as usize {
            return Err(Error::TooShort);
        }
        if !input.starts_with(RAR13_SIGNATURE) {
            return Err(Error::UnsupportedSignature);
        }

        let head_size = read_u16(input, 4)?;
        let flags = input[6];
        if head_size < MAIN_HEAD_SIZE {
            return Err(Error::InvalidHeader(
                "RAR 1.3 main header is shorter than 7 bytes",
            ));
        }
        if head_size as usize > input.len() {
            return Err(Error::TooShort);
        }

        let extra = input[MAIN_HEAD_SIZE as usize..head_size as usize].to_vec();

        Ok(Self {
            flags,
            head_size,
            extra,
        })
    }
}

impl FileHeader {
    fn parse(input: &[u8]) -> Result<(Self, Vec<u8>, Vec<u8>, usize)> {
        if input.len() < FILE_HEAD_BASE_SIZE {
            return Err(Error::TooShort);
        }

        let pack_size = read_u32(input, 0)?;
        let unp_size = read_u32(input, 4)?;
        let file_crc = read_u16(input, 8)?;
        let head_size = read_u16(input, 10)?;
        let file_time = read_u32(input, 12)?;
        let file_attr = input[16];
        let flags = input[17];
        let unp_ver = input[18];
        let name_size = input[19] as usize;
        let method = input[20];
        let minimum_size = FILE_HEAD_BASE_SIZE + name_size;

        if (head_size as usize) < minimum_size {
            return Err(Error::InvalidHeader(
                "RAR 1.3 file header is shorter than its name",
            ));
        }
        if input.len() < head_size as usize {
            return Err(Error::TooShort);
        }

        let name = input[FILE_HEAD_BASE_SIZE..FILE_HEAD_BASE_SIZE + name_size].to_vec();
        let extra = input[minimum_size..head_size as usize].to_vec();
        Ok((
            Self {
                flags,
                pack_size,
                unp_size,
                file_crc,
                file_time,
                file_attr,
                unp_ver,
                method,
                head_size,
            },
            name,
            extra,
            head_size as usize,
        ))
    }
}

impl Archive {
    pub fn parse(input: &[u8]) -> Result<Self> {
        let data: Arc<[u8]> = Arc::from(input.to_vec().into_boxed_slice());
        Self::parse_shared(data)
    }

    pub fn parse_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = Arc::new(path.as_ref().to_path_buf());
        let mut file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        let scan_len = len.min(128 * 1024) as usize;
        let mut scan = vec![0; scan_len];
        file.read_exact(&mut scan)?;
        let sig = find_archive_start(&scan, 128 * 1024).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar13 {
            return Err(Error::UnsupportedSignature);
        }
        Self::parse_seekable(file, len, sig.offset, ArchiveSource::File(path))
    }

    fn parse_shared(input: Arc<[u8]>) -> Result<Self> {
        let sig = find_archive_start(&input, 128 * 1024).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar13 {
            return Err(Error::UnsupportedSignature);
        }

        let archive = &input[sig.offset..];
        let main = MainHeader::parse(archive)?;
        let mut pos = main.head_size as usize;
        let mut entries = Vec::new();

        while pos < archive.len() {
            if archive.len() - pos < FILE_HEAD_BASE_SIZE {
                break;
            }

            let (header, name, extra, consumed) = FileHeader::parse(&archive[pos..])?;
            let data_start = pos + consumed;
            let data_end =
                data_start
                    .checked_add(header.pack_size as usize)
                    .ok_or(Error::InvalidHeader(
                        "RAR 1.3 file data size overflows usize",
                    ))?;
            if data_end > archive.len() {
                return Err(Error::TooShort);
            }

            entries.push(Entry {
                header,
                name,
                extra,
                packed_range: sig.offset + data_start..sig.offset + data_end,
            });
            pos = data_end;
        }

        Ok(Self {
            sfx_offset: sig.offset,
            main,
            entries,
            source: ArchiveSource::Memory(input),
        })
    }

    fn parse_seekable(
        mut file: File,
        file_len: u64,
        sfx_offset: usize,
        source: ArchiveSource,
    ) -> Result<Self> {
        let main_prefix = read_exact_at(&mut file, sfx_offset, MAIN_HEAD_SIZE as usize)?;
        let head_size = read_u16(&main_prefix, 4)? as usize;
        let main_bytes = read_exact_at(&mut file, sfx_offset, head_size)?;
        let main = MainHeader::parse(&main_bytes)?;
        let mut pos = main.head_size as usize;
        let mut entries = Vec::new();

        while (sfx_offset + pos) as u64 + FILE_HEAD_BASE_SIZE as u64 <= file_len {
            let header_prefix = read_exact_at(&mut file, sfx_offset + pos, FILE_HEAD_BASE_SIZE)?;
            let head_size = read_u16(&header_prefix, 10)? as usize;
            let header_bytes = read_exact_at(&mut file, sfx_offset + pos, head_size)?;
            let (header, name, extra, consumed) = FileHeader::parse(&header_bytes)?;
            let data_start = pos + consumed;
            let data_end =
                data_start
                    .checked_add(header.pack_size as usize)
                    .ok_or(Error::InvalidHeader(
                        "RAR 1.3 file data size overflows usize",
                    ))?;
            if (sfx_offset + data_end) as u64 > file_len {
                return Err(Error::TooShort);
            }
            entries.push(Entry {
                header,
                name,
                extra,
                packed_range: sfx_offset + data_start..sfx_offset + data_end,
            });
            pos = data_end;
        }

        Ok(Self {
            sfx_offset,
            main,
            entries,
            source,
        })
    }

    fn read_range(&self, range: Range<usize>) -> Result<Vec<u8>> {
        match &self.source {
            ArchiveSource::Memory(data) => data
                .get(range)
                .map(|data| data.to_vec())
                .ok_or(Error::TooShort),
            ArchiveSource::File(path) => {
                let mut file = File::open(path.as_ref())?;
                read_exact_at(&mut file, range.start, range.len())
            }
        }
    }

    fn copy_range_to(&self, range: Range<usize>, out: &mut impl Write) -> Result<()> {
        match &self.source {
            ArchiveSource::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                out.write_all(data)?;
            }
            ArchiveSource::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
                let mut limited = file.take(range.len() as u64);
                std::io::copy(&mut limited, out)?;
            }
        }
        Ok(())
    }

    fn range_reader(&self, range: Range<usize>) -> Result<Box<dyn Read + '_>> {
        match &self.source {
            ArchiveSource::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                Ok(Box::new(Cursor::new(data)))
            }
            ArchiveSource::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
                Ok(Box::new(file.take(range.len() as u64)))
            }
        }
    }

    fn copy_decrypted_range_to(
        &self,
        range: Range<usize>,
        mut cipher: Rar13Cipher,
        out: &mut impl Write,
    ) -> Result<()> {
        let mut buffer = [0u8; COPY_BUFFER_SIZE];
        match &self.source {
            ArchiveSource::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                for chunk in data.chunks(COPY_BUFFER_SIZE) {
                    buffer[..chunk.len()].copy_from_slice(chunk);
                    for byte in &mut buffer[..chunk.len()] {
                        *byte = cipher.decrypt_byte(*byte);
                    }
                    out.write_all(&buffer[..chunk.len()])?;
                }
            }
            ArchiveSource::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
                let mut remaining = range.len();
                while remaining > 0 {
                    let to_read = remaining.min(buffer.len());
                    file.read_exact(&mut buffer[..to_read])?;
                    for byte in &mut buffer[..to_read] {
                        *byte = cipher.decrypt_byte(*byte);
                    }
                    out.write_all(&buffer[..to_read])?;
                    remaining -= to_read;
                }
            }
        }
        Ok(())
    }

    pub fn extract_stored(&self, password: Option<&[u8]>) -> Result<Vec<ExtractedEntry>> {
        let mut out = Vec::new();
        for entry in &self.entries {
            if entry.is_split_before() || entry.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 split entry requires multivolume extraction",
                ));
            }
            out.push(entry.extract_stored(self, password)?);
        }
        Ok(out)
    }

    /// Convenience extraction API that buffers each extracted entry in memory.
    ///
    /// Prefer [`Archive::extract_to`] for large archives.
    pub fn extract(&self, password: Option<&[u8]>) -> Result<Vec<ExtractedEntry>> {
        let mut out = Vec::new();
        let mut unpack15 = Unpack15::new();
        for entry in &self.entries {
            if entry.is_split_before() || entry.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 split entry requires multivolume extraction",
                ));
            }
            out.push(entry.extract_with_context(
                self,
                password,
                Some(&mut unpack15),
                self.main.is_solid() && !out.is_empty(),
            )?);
        }
        Ok(out)
    }

    /// Streams extracted entries to caller-provided writers.
    pub fn extract_to<F>(&self, password: Option<&[u8]>, mut open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let mut unpack15 = Unpack15::new();
        let mut extracted_count = 0usize;
        for entry in &self.entries {
            if entry.is_split_before() || entry.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 split entry requires multivolume extraction",
                ));
            }
            let meta = entry.metadata();
            if meta.is_directory {
                let _ = open(&meta)?;
                extracted_count += 1;
                continue;
            }
            let mut writer = open(&meta)?;
            if entry.is_stored() && !entry.is_encrypted() {
                entry.write_stored_to(self, password, &mut writer)?;
            } else {
                entry.write_compressed_to(
                    self,
                    password,
                    &mut unpack15,
                    self.main.is_solid() && extracted_count != 0,
                    &mut writer,
                )?;
            }
            extracted_count += 1;
        }
        Ok(())
    }

    pub fn archive_comment(&self) -> Result<Option<Vec<u8>>> {
        if !self.main.has_archive_comment() {
            return Ok(None);
        }

        let length = read_u16(&self.main.extra, 0)? as usize;
        if self.main.has_packed_comment() {
            if length < 2 {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 packed archive comment is shorter than size field",
                ));
            }
            let unpacked_len = read_u16(&self.main.extra, 2)? as usize;
            let packed_len = length - 2;
            let packed_start = 4usize;
            let packed_end = packed_start
                .checked_add(packed_len)
                .ok_or(Error::InvalidHeader(
                    "RAR 1.3 archive comment size overflows",
                ))?;
            if packed_end > self.main.extra.len() {
                return Err(Error::TooShort);
            }

            let mut packed = self.main.extra[packed_start..packed_end].to_vec();
            Rar13Cipher::new_comment().decrypt_in_place(&mut packed);
            return Ok(Some(unpack15_decode(&packed, unpacked_len)?));
        }

        let comment_start = 2usize;
        let comment_end = comment_start
            .checked_add(length)
            .ok_or(Error::InvalidHeader(
                "RAR 1.3 archive comment size overflows",
            ))?;
        if comment_end > self.main.extra.len() {
            return Err(Error::TooShort);
        }
        Ok(Some(self.main.extra[comment_start..comment_end].to_vec()))
    }

    pub fn authenticity_verification(&self) -> Result<Option<AuthenticityVerification>> {
        if !self.main.has_authenticity_verification() {
            return Ok(None);
        }
        let size = read_u16(&self.main.extra, 0)?;
        if size < RAR13_AV_PREFIX.len() as u16 {
            return Err(Error::InvalidHeader("RAR 1.3 AV payload is too short"));
        }
        let payload_end = 2usize
            .checked_add(size as usize)
            .ok_or(Error::InvalidHeader("RAR 1.3 AV payload size overflows"))?;
        if payload_end > self.main.extra.len() {
            return Err(Error::TooShort);
        }
        let prefix_bytes = self
            .main
            .extra
            .get(2..2 + RAR13_AV_PREFIX.len())
            .ok_or(Error::TooShort)?;
        let prefix: [u8; 6] = prefix_bytes
            .try_into()
            .expect("RAR 1.3 AV prefix slice has fixed length");
        if &prefix != RAR13_AV_PREFIX {
            return Err(Error::InvalidHeader("RAR 1.3 AV prefix mismatch"));
        }
        Ok(Some(AuthenticityVerification {
            size,
            prefix,
            cipher_body: self.main.extra[2 + RAR13_AV_PREFIX.len()..payload_end].to_vec(),
        }))
    }

    pub fn verify_authenticity_verification(&self) -> Result<AuthenticityVerificationStatus> {
        Ok(if self.authenticity_verification()?.is_some() {
            AuthenticityVerificationStatus::StructurallyValid
        } else {
            AuthenticityVerificationStatus::Absent
        })
    }
}

impl Entry {
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    pub fn is_encrypted(&self) -> bool {
        self.header.flags & LHD_PASSWORD != 0
    }

    pub fn is_split_before(&self) -> bool {
        self.header.flags & LHD_SPLIT_BEFORE != 0
    }

    pub fn is_split_after(&self) -> bool {
        self.header.flags & LHD_SPLIT_AFTER != 0
    }

    pub fn is_directory(&self) -> bool {
        self.header.file_attr & 0x10 != 0
    }

    pub fn has_file_comment(&self) -> bool {
        self.header.flags & LHD_COMMENT != 0
    }

    pub fn file_comment(&self) -> Result<Option<Vec<u8>>> {
        if !self.has_file_comment() {
            return Ok(None);
        }
        let length = read_u16(&self.extra, 0)? as usize;
        let comment_start = 2usize;
        let comment_end = comment_start
            .checked_add(length)
            .ok_or(Error::InvalidHeader("RAR 1.3 file comment size overflows"))?;
        if comment_end > self.extra.len() {
            return Err(Error::TooShort);
        }
        Ok(Some(self.extra[comment_start..comment_end].to_vec()))
    }

    pub fn is_stored(&self) -> bool {
        self.header.method == METHOD_STORE
    }

    pub fn packed_data<'a>(&self, archive: &'a Archive) -> Result<&'a [u8]> {
        match &archive.source {
            ArchiveSource::Memory(data) => {
                data.get(self.packed_range.clone()).ok_or(Error::TooShort)
            }
            ArchiveSource::File(_) => Err(Error::InvalidHeader(
                "RAR 1.3 file-backed packed data requires owned read",
            )),
        }
    }

    pub fn packed_data_owned(&self, archive: &Archive) -> Result<Vec<u8>> {
        archive.read_range(self.packed_range.clone())
    }

    pub fn write_packed_data(&self, archive: &Archive, out: &mut impl Write) -> Result<()> {
        archive.copy_range_to(self.packed_range.clone(), out)
    }

    pub fn stored_data(&self, archive: &Archive, password: Option<&[u8]>) -> Result<Vec<u8>> {
        if !self.is_stored() {
            return Err(Error::InvalidHeader("RAR 1.3 entry is not stored"));
        }

        self.decrypt_packed_data(archive, password)
    }

    fn decrypt_packed_data(&self, archive: &Archive, password: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut data = self.packed_data_owned(archive)?;
        if self.is_encrypted() {
            let password = password.ok_or(Error::NeedPassword)?;
            Rar13Cipher::new(password).decrypt_in_place(&mut data);
        }

        Ok(data)
    }

    pub fn verify_checksum(&self, data: &[u8]) -> Result<()> {
        let actual = file_checksum(data);
        if actual == self.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: self.header.file_crc,
                actual,
            })
        }
    }

    pub fn metadata(&self) -> ExtractedEntryMeta {
        ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.header.file_time,
            file_attr: self.header.file_attr,
            is_directory: self.is_directory(),
        }
    }

    pub fn extract_stored(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<ExtractedEntry> {
        if self.is_directory() {
            return Ok(ExtractedEntry {
                name: self.name.clone(),
                data: Vec::new(),
                file_time: self.header.file_time,
                file_attr: self.header.file_attr,
                is_directory: true,
            });
        }

        let data = self.stored_data(archive, password)?;
        self.verify_checksum(&data)?;
        Ok(ExtractedEntry {
            name: self.name.clone(),
            data,
            file_time: self.header.file_time,
            file_attr: self.header.file_attr,
            is_directory: self.is_directory(),
        })
    }

    fn write_stored_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if !self.is_stored() {
            return Err(Error::InvalidHeader("RAR 1.3 entry is not stored"));
        }
        if self.is_encrypted() {
            let password = password.ok_or(Error::NeedPassword)?;
            let mut checksum = Rar13Checksum::new();
            let mut checksum_writer = Rar13ChecksumWriter {
                inner: out,
                checksum: &mut checksum,
            };
            archive.copy_decrypted_range_to(
                self.packed_range.clone(),
                Rar13Cipher::new(password),
                &mut checksum_writer,
            )?;
            let actual = checksum.finish();
            return if actual == self.header.file_crc {
                Ok(())
            } else {
                Err(Error::CrcMismatch {
                    expected: self.header.file_crc,
                    actual,
                })
            };
        }
        let mut checksum = Rar13Checksum::new();
        let mut checksum_writer = Rar13ChecksumWriter {
            inner: out,
            checksum: &mut checksum,
        };
        self.write_packed_data(archive, &mut checksum_writer)?;
        let actual = checksum.finish();
        if actual == self.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: self.header.file_crc,
                actual,
            })
        }
    }

    fn write_compressed_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        unpack15: &mut Unpack15,
        solid: bool,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_stored() || self.is_directory() {
            return self.write_stored_to(archive, password, out);
        }
        let mut checksum = Rar13Checksum::new();
        let mut checksum_writer = Rar13ChecksumWriter {
            inner: out,
            checksum: &mut checksum,
        };
        if self.is_encrypted() {
            let password = password.ok_or(Error::NeedPassword)?;
            let packed = archive.range_reader(self.packed_range.clone())?;
            let mut packed = Rar13DecryptReader::new(packed, Rar13Cipher::new(password));
            unpack15.decode_member_from_reader(
                &mut packed,
                self.header.unp_size as usize,
                solid,
                &mut checksum_writer,
            )?;
        } else {
            let mut packed = archive.range_reader(self.packed_range.clone())?;
            unpack15.decode_member_from_reader(
                &mut packed,
                self.header.unp_size as usize,
                solid,
                &mut checksum_writer,
            )?;
        }
        let actual = checksum.finish();
        if actual == self.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: self.header.file_crc,
                actual,
            })
        }
    }

    pub fn extract(&self, archive: &Archive, password: Option<&[u8]>) -> Result<ExtractedEntry> {
        self.extract_with_context(archive, password, None, false)
    }

    fn extract_with_context(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        unpack15: Option<&mut Unpack15>,
        solid: bool,
    ) -> Result<ExtractedEntry> {
        if self.is_stored() || self.is_directory() {
            return self.extract_stored(archive, password);
        }

        let packed = self.decrypt_packed_data(archive, password)?;
        let data = if let Some(unpack15) = unpack15 {
            unpack15.decode_member(&packed, self.header.unp_size as usize, solid)?
        } else {
            unpack15_decode(&packed, self.header.unp_size as usize)?
        };
        self.verify_checksum(&data)?;
        Ok(ExtractedEntry {
            name: self.name.clone(),
            data,
            file_time: self.header.file_time,
            file_attr: self.header.file_attr,
            is_directory: false,
        })
    }
}

/// Convenience multivolume extraction API that buffers each extracted entry in
/// memory. Prefer [`extract_volumes_to`] for large archives.
pub fn extract_volumes(
    volumes: &[Archive],
    password: Option<&[u8]>,
) -> Result<Vec<ExtractedEntry>> {
    let mut out = Vec::new();
    let mut pending: Option<PendingSplit> = None;
    let mut unpack15 = Unpack15::new();

    for archive in volumes {
        for entry in &archive.entries {
            if !entry.is_split_before() && !entry.is_split_after() {
                if pending.is_some() {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry is interrupted by a regular entry",
                    ));
                }
                let solid = archive.main.is_solid() && !out.is_empty();
                out.push(entry.extract_with_context(
                    archive,
                    password,
                    Some(&mut unpack15),
                    solid,
                )?);
                continue;
            }

            let data = entry.decrypt_packed_data(archive, password)?;
            match (
                &mut pending,
                entry.is_split_before(),
                entry.is_split_after(),
            ) {
                (None, false, true) => {
                    pending = Some(PendingSplit::new(entry, data));
                }
                (Some(current), true, true) => {
                    current.append(entry, data)?;
                }
                (Some(current), true, false) => {
                    current.append(entry, data)?;
                    let completed = pending.take().expect("pending split");
                    let solid = archive.main.is_solid() && !out.is_empty();
                    out.push(completed.finish(entry, &mut unpack15, solid)?);
                }
                _ => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry flags are inconsistent",
                    ));
                }
            }
        }
    }

    if pending.is_some() {
        return Err(Error::InvalidHeader("RAR 1.3 split entry is incomplete"));
    }

    Ok(out)
}

/// Streams a multivolume archive set to caller-provided writers.
pub fn extract_volumes_to<F>(
    volumes: &[Archive],
    password: Option<&[u8]>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    let mut pending: Option<PendingSplitRefs> = None;
    let mut unpack15 = Unpack15::new();
    let mut extracted_count = 0usize;

    for (volume_index, archive) in volumes.iter().enumerate() {
        for (entry_index, entry) in archive.entries.iter().enumerate() {
            if !entry.is_split_before() && !entry.is_split_after() {
                if pending.is_some() {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry is interrupted by a regular entry",
                    ));
                }
                let meta = entry.metadata();
                if meta.is_directory {
                    let _ = open(&meta)?;
                    extracted_count += 1;
                    continue;
                }
                let mut writer = open(&meta)?;
                entry.write_compressed_to(
                    archive,
                    password,
                    &mut unpack15,
                    archive.main.is_solid() && extracted_count != 0,
                    &mut writer,
                )?;
                extracted_count += 1;
                continue;
            }

            match (
                &mut pending,
                entry.is_split_before(),
                entry.is_split_after(),
            ) {
                (None, false, true) => {
                    pending = Some(PendingSplitRefs::new(entry, volume_index, entry_index));
                }
                (Some(current), true, true) => {
                    current.append(entry, volume_index, entry_index)?;
                }
                (Some(current), true, false) => {
                    current.append(entry, volume_index, entry_index)?;
                    let completed = pending.take().expect("pending split");
                    let solid = archive.main.is_solid() && extracted_count != 0;
                    completed.write_to(
                        volumes,
                        entry,
                        password,
                        &mut unpack15,
                        solid,
                        &mut open,
                    )?;
                    extracted_count += 1;
                }
                _ => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry flags are inconsistent",
                    ));
                }
            }
        }
    }

    if pending.is_some() {
        return Err(Error::InvalidHeader("RAR 1.3 split entry is incomplete"));
    }

    Ok(())
}

pub fn extract_stored_volumes(
    volumes: &[Archive],
    password: Option<&[u8]>,
) -> Result<Vec<ExtractedEntry>> {
    extract_volumes(volumes, password)
}

fn read_exact_at(file: &mut File, offset: usize, len: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset as u64))?;
    let mut data = vec![0; len];
    file.read_exact(&mut data)?;
    Ok(data)
}

struct Rar13ChecksumWriter<'a, W: Write + ?Sized> {
    inner: &'a mut W,
    checksum: &'a mut Rar13Checksum,
}

impl<W: Write + ?Sized> Write for Rar13ChecksumWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.checksum.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct Rar13Checksum {
    value: u16,
}

impl Rar13Checksum {
    fn new() -> Self {
        Self { value: 0 }
    }

    fn update(&mut self, input: &[u8]) {
        for &byte in input {
            self.value = self.value.wrapping_add(byte as u16).rotate_left(1);
        }
    }

    fn finish(self) -> u16 {
        self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingSplit {
    name: Vec<u8>,
    packed_data: Vec<u8>,
    file_time: u32,
    file_attr: u8,
    method: u8,
    unp_ver: u8,
    was_encrypted: bool,
}

struct PendingSplitRefs {
    name: Vec<u8>,
    fragments: Vec<(usize, usize)>,
    file_time: u32,
    file_attr: u8,
    method: u8,
    unp_ver: u8,
    was_encrypted: bool,
}

impl PendingSplitRefs {
    fn new(entry: &Entry, volume_index: usize, entry_index: usize) -> Self {
        Self {
            name: entry.name.clone(),
            fragments: vec![(volume_index, entry_index)],
            file_time: entry.header.file_time,
            file_attr: entry.header.file_attr,
            method: entry.header.method,
            unp_ver: entry.header.unp_ver,
            was_encrypted: entry.is_encrypted(),
        }
    }

    fn append(&mut self, entry: &Entry, volume_index: usize, entry_index: usize) -> Result<()> {
        if entry.name != self.name {
            return Err(Error::InvalidHeader("RAR 1.3 split entry name changed"));
        }
        if entry.header.method != self.method {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry compression method changed",
            ));
        }
        if entry.header.unp_ver != self.unp_ver {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry unpack version changed",
            ));
        }
        if entry.is_encrypted() != self.was_encrypted {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry encryption flag changed",
            ));
        }
        self.fragments.push((volume_index, entry_index));
        Ok(())
    }

    fn write_to<F>(
        self,
        volumes: &[Archive],
        final_entry: &Entry,
        password: Option<&[u8]>,
        unpack15: &mut Unpack15,
        solid: bool,
        open: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let mut reader = self.fragment_reader(volumes, password)?;
        let meta = ExtractedEntryMeta {
            name: self.name,
            file_time: self.file_time,
            file_attr: self.file_attr,
            is_directory: false,
        };
        let mut writer = open(&meta)?;
        let mut checksum = Rar13Checksum::new();
        let mut checksum_writer = Rar13ChecksumWriter {
            inner: &mut writer,
            checksum: &mut checksum,
        };
        if self.method == METHOD_STORE {
            std::io::copy(&mut reader, &mut checksum_writer)?;
        } else {
            unpack15.decode_member_from_reader(
                &mut reader,
                final_entry.header.unp_size as usize,
                solid,
                &mut checksum_writer,
            )?;
        }
        let actual = checksum.finish();
        if actual == final_entry.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: final_entry.header.file_crc,
                actual,
            })
        }
    }

    fn fragment_reader<'a>(
        &self,
        volumes: &'a [Archive],
        password: Option<&'a [u8]>,
    ) -> Result<ChainedReader<'a>> {
        let mut readers = Vec::with_capacity(self.fragments.len());
        for &(volume_index, entry_index) in &self.fragments {
            let archive = volumes
                .get(volume_index)
                .ok_or(Error::InvalidHeader("RAR 1.3 split volume is missing"))?;
            let entry = archive
                .entries
                .get(entry_index)
                .ok_or(Error::InvalidHeader("RAR 1.3 split entry is missing"))?;
            let reader = archive.range_reader(entry.packed_range.clone())?;
            if entry.is_encrypted() {
                let password = password.ok_or(Error::NeedPassword)?;
                readers.push(
                    Box::new(Rar13DecryptReader::new(reader, Rar13Cipher::new(password)))
                        as Box<dyn Read + 'a>,
                );
            } else {
                readers.push(reader);
            }
        }
        Ok(ChainedReader { readers, index: 0 })
    }
}

struct ChainedReader<'a> {
    readers: Vec<Box<dyn Read + 'a>>,
    index: usize,
}

impl Read for ChainedReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while let Some(reader) = self.readers.get_mut(self.index) {
            let read = reader.read(out)?;
            if read != 0 {
                return Ok(read);
            }
            self.index += 1;
        }
        Ok(0)
    }
}

impl PendingSplit {
    fn new(entry: &Entry, packed_data: Vec<u8>) -> Self {
        Self {
            name: entry.name.clone(),
            packed_data,
            file_time: entry.header.file_time,
            file_attr: entry.header.file_attr,
            method: entry.header.method,
            unp_ver: entry.header.unp_ver,
            was_encrypted: entry.is_encrypted(),
        }
    }

    fn append(&mut self, entry: &Entry, packed_data: Vec<u8>) -> Result<()> {
        if entry.name != self.name {
            return Err(Error::InvalidHeader("RAR 1.3 split entry name changed"));
        }
        if entry.header.method != self.method {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry compression method changed",
            ));
        }
        if entry.is_encrypted() != self.was_encrypted {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry encryption flag changed",
            ));
        }
        self.packed_data.extend_from_slice(&packed_data);
        Ok(())
    }

    fn finish(
        self,
        final_entry: &Entry,
        unpack15: &mut Unpack15,
        solid: bool,
    ) -> Result<ExtractedEntry> {
        let data = if self.method == METHOD_STORE {
            self.packed_data
        } else {
            unpack15.decode_member(
                &self.packed_data,
                final_entry.header.unp_size as usize,
                solid,
            )?
        };
        final_entry.verify_checksum(&data)?;
        Ok(ExtractedEntry {
            name: self.name,
            data,
            file_time: self.file_time,
            file_attr: self.file_attr,
            is_directory: false,
        })
    }
}

pub fn write_stored_archive(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_stored_archive_with_comment(entries, options, None)
}

pub fn write_stored_archive_with_comment(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    options.features.validate_for(options.target)?;
    validate_stored_writer_features(options.target, options.features)?;

    let mut out = Vec::new();
    write_main_header(&mut out, options.features, archive_comment)?;

    for entry in entries {
        validate_stored_entry(entry)?;
        write_stored_entry(&mut out, entry, options.features)?;
    }

    Ok(out)
}

pub fn write_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_compressed_archive_with_comment(entries, options, None)
}

pub fn write_compressed_archive_with_comment(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    options.features.validate_for(options.target)?;
    validate_compressed_writer_features(options.target, options.features)?;

    let mut out = Vec::new();
    write_main_header(&mut out, options.features, archive_comment)?;

    let mut solid_encoder = options.features.solid.then(Unpack15Encoder::new);

    for entry in entries {
        validate_file_entry(entry.name, entry.data)?;
        let mut packed = if let Some(encoder) = solid_encoder.as_mut() {
            encoder.encode_member(entry.data)?
        } else {
            unpack15_encode(entry.data)?
        };
        if let Some(password) = entry.password {
            Rar13Cipher::new(password).encrypt_in_place(&mut packed);
        }
        let mut flags = 0;
        if options.features.solid {
            flags |= LHD_SOLID;
        }
        if entry.password.is_some() {
            flags |= LHD_PASSWORD;
        }
        if entry.file_comment.is_some() {
            flags |= LHD_COMMENT;
        }
        let file_extra = encode_file_comment(entry.file_comment)?;
        write_file_entry(
            &mut out,
            entry.name,
            entry.data,
            &packed,
            entry.file_time,
            entry.file_attr,
            flags,
            DEFAULT_UNP_VER,
            3,
            &file_extra,
        )?;
    }

    Ok(out)
}

pub fn write_stored_volumes(
    entry: StoredEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    options.features.validate_for(options.target)?;
    validate_stored_writer_features(options.target, options.features)?;
    validate_volume_writer_inputs(
        entry.name,
        entry.data,
        entry.password,
        entry.file_comment,
        options,
    )?;

    let body = entry.data.to_vec();
    write_split_volumes(
        entry.name,
        entry.data,
        &body,
        entry.file_time,
        entry.file_attr,
        METHOD_STORE,
        0,
        options.features,
        max_packed_per_volume,
    )
}

pub fn write_compressed_volumes(
    entry: FileEntry<'_>,
    options: WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    options.features.validate_for(options.target)?;
    validate_compressed_writer_features(options.target, options.features)?;
    validate_volume_writer_inputs(
        entry.name,
        entry.data,
        entry.password,
        entry.file_comment,
        options,
    )?;

    let packed = unpack15_encode(entry.data)?;
    write_split_volumes(
        entry.name,
        entry.data,
        &packed,
        entry.file_time,
        entry.file_attr,
        3,
        0,
        options.features,
        max_packed_per_volume,
    )
}

fn validate_stored_writer_features(version: ArchiveVersion, features: FeatureSet) -> Result<()> {
    reject_writer_feature(version, features.sfx, "sfx")?;
    reject_writer_feature(
        version,
        features.authenticity_verification,
        "authenticity_verification",
    )?;
    Ok(())
}

fn validate_volume_writer_inputs(
    name: &[u8],
    data: &[u8],
    password: Option<&[u8]>,
    file_comment: Option<&[u8]>,
    options: WriterOptions,
) -> Result<()> {
    validate_file_entry(name, data)?;
    if password.is_some() {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "volume_password",
        });
    }
    if file_comment.is_some() || options.features.file_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "volume_file_comment",
        });
    }
    if options.features.archive_comment {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "volume_archive_comment",
        });
    }
    Ok(())
}

fn validate_compressed_writer_features(
    version: ArchiveVersion,
    features: FeatureSet,
) -> Result<()> {
    reject_writer_feature(version, features.sfx, "sfx")?;
    reject_writer_feature(
        version,
        features.authenticity_verification,
        "authenticity_verification",
    )?;
    Ok(())
}

fn reject_writer_feature(
    version: ArchiveVersion,
    enabled: bool,
    feature: &'static str,
) -> Result<()> {
    if enabled {
        Err(Error::UnsupportedFeature { version, feature })
    } else {
        Ok(())
    }
}

fn write_main_header(
    out: &mut Vec<u8>,
    features: FeatureSet,
    archive_comment: Option<&[u8]>,
) -> Result<()> {
    write_main_header_with_flags(out, features, archive_comment, 0)
}

fn write_main_header_with_flags(
    out: &mut Vec<u8>,
    features: FeatureSet,
    archive_comment: Option<&[u8]>,
    extra_flags: u8,
) -> Result<()> {
    let comment_extra = encode_archive_comment(archive_comment)?;
    let mut flags = MHD_ALWAYS_SET | extra_flags;
    if archive_comment.is_some() {
        flags |= MHD_COMMENT;
        flags |= MHD_PACK_COMMENT;
    }
    if features.solid {
        flags |= MHD_SOLID;
    }
    out.extend_from_slice(RAR13_SIGNATURE);
    let head_size = MAIN_HEAD_SIZE as usize + comment_extra.len();
    if head_size > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 main header comment extension is too large",
        ));
    }
    out.extend_from_slice(&(head_size as u16).to_le_bytes());
    out.push(flags);
    out.extend_from_slice(&comment_extra);
    Ok(())
}

fn write_stored_entry(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    features: FeatureSet,
) -> Result<()> {
    let mut flags = 0u8;
    if entry.password.is_some() {
        flags |= LHD_PASSWORD;
    }
    if entry.file_comment.is_some() {
        flags |= LHD_COMMENT;
    }
    if features.solid {
        flags |= LHD_SOLID;
    }

    let mut body = entry.data.to_vec();
    if let Some(password) = entry.password {
        Rar13Cipher::new(password).encrypt_in_place(&mut body);
    }

    let file_extra = encode_file_comment(entry.file_comment)?;
    write_file_entry(
        out,
        entry.name,
        entry.data,
        &body,
        entry.file_time,
        entry.file_attr,
        flags,
        DEFAULT_UNP_VER,
        METHOD_STORE,
        &file_extra,
    )?;
    Ok(())
}

fn validate_stored_entry(entry: &StoredEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name, entry.data)
}

#[allow(clippy::too_many_arguments)]
fn write_file_entry(
    out: &mut Vec<u8>,
    name: &[u8],
    unpacked: &[u8],
    packed: &[u8],
    file_time: u32,
    file_attr: u8,
    flags: u8,
    unp_ver: u8,
    method: u8,
    extra: &[u8],
) -> Result<()> {
    write_file_entry_with_crc(
        out,
        name,
        unpacked.len() as u32,
        file_checksum(unpacked),
        packed,
        file_time,
        file_attr,
        flags,
        unp_ver,
        method,
        extra,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_file_entry_with_crc(
    out: &mut Vec<u8>,
    name: &[u8],
    unpacked_size: u32,
    file_crc: u16,
    packed: &[u8],
    file_time: u32,
    file_attr: u8,
    flags: u8,
    unp_ver: u8,
    method: u8,
    extra: &[u8],
) -> Result<()> {
    let head_size = FILE_HEAD_BASE_SIZE + name.len() + extra.len();
    out.extend_from_slice(&(packed.len() as u32).to_le_bytes());
    out.extend_from_slice(&unpacked_size.to_le_bytes());
    out.extend_from_slice(&file_crc.to_le_bytes());
    out.extend_from_slice(&(head_size as u16).to_le_bytes());
    out.extend_from_slice(&file_time.to_le_bytes());
    out.push(file_attr);
    out.push(flags);
    out.push(unp_ver);
    out.push(name.len() as u8);
    out.push(method);
    out.extend_from_slice(name);
    out.extend_from_slice(extra);
    out.extend_from_slice(packed);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_split_volumes(
    name: &[u8],
    unpacked: &[u8],
    packed: &[u8],
    file_time: u32,
    file_attr: u8,
    method: u8,
    base_flags: u8,
    features: FeatureSet,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>> {
    if max_packed_per_volume == 0 {
        return Err(Error::InvalidHeader(
            "RAR 1.3 volume payload size must be non-zero",
        ));
    }
    if packed.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 1.3 volume writer needs a non-empty packed payload",
        ));
    }

    let chunks: Vec<&[u8]> = packed.chunks(max_packed_per_volume).collect();
    if chunks.len() < 2 {
        return Err(Error::InvalidHeader(
            "RAR 1.3 volume writer needs at least two volumes",
        ));
    }

    let mut volumes = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.iter().enumerate() {
        let split_before = index > 0;
        let split_after = index + 1 < chunks.len();
        let mut flags = base_flags;
        if split_before {
            flags |= LHD_SPLIT_BEFORE;
        }
        if split_after {
            flags |= LHD_SPLIT_AFTER;
        }
        if features.solid {
            flags |= LHD_SOLID;
        }

        let mut out = Vec::new();
        write_main_header_with_flags(&mut out, features, None, MHD_VOLUME)?;
        let checksum_data = if split_after { *chunk } else { unpacked };
        write_file_entry_with_crc(
            &mut out,
            name,
            unpacked.len() as u32,
            file_checksum(checksum_data),
            chunk,
            file_time,
            file_attr,
            flags,
            DEFAULT_UNP_VER,
            method,
            &[],
        )?;
        volumes.push(out);
    }

    Ok(volumes)
}

fn encode_archive_comment(comment: Option<&[u8]>) -> Result<Vec<u8>> {
    let Some(comment) = comment else {
        return Ok(Vec::new());
    };
    if comment.len() > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 archive comment is longer than 65535 bytes",
        ));
    }
    let mut packed = unpack15_encode(comment)?;
    Rar13Cipher::new_comment().encrypt_in_place(&mut packed);
    let packed_field_len = packed.len().checked_add(2).ok_or(Error::InvalidHeader(
        "RAR 1.3 archive comment size overflows",
    ))?;
    if packed_field_len > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 packed archive comment is longer than 65535 bytes",
        ));
    }

    let mut out = Vec::with_capacity(4 + packed.len());
    out.extend_from_slice(&(packed_field_len as u16).to_le_bytes());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(&packed);
    Ok(out)
}

fn encode_file_comment(comment: Option<&[u8]>) -> Result<Vec<u8>> {
    let Some(comment) = comment else {
        return Ok(Vec::new());
    };
    if comment.len() > u16::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 file comment is longer than 65535 bytes",
        ));
    }
    let mut out = Vec::with_capacity(2 + comment.len());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    Ok(out)
}

fn validate_file_entry(name: &[u8], data: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.3 file name is empty"));
    }
    if name.len() > u8::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 file name is longer than 255 bytes",
        ));
    }
    if data.len() > u32::MAX as usize {
        return Err(Error::InvalidHeader(
            "RAR 1.3 file is larger than 32-bit size fields",
        ));
    }
    Ok(())
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16> {
    let bytes = input.get(offset..offset + 2).ok_or(Error::TooShort)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32> {
    let bytes = input.get(offset..offset + 4).ok_or(Error::TooShort)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub fn file_checksum(input: &[u8]) -> u16 {
    let mut checksum = Rar13Checksum::new();
    checksum.update(input);
    checksum.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{find_long_lz, LongLz};

    #[test]
    fn writes_and_reads_stored_archive() {
        let input = [
            StoredEntry {
                name: b"README.md",
                data: b"hello rar 1.3",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            StoredEntry {
                name: b"docs",
                data: b"",
                file_time: 0,
                file_attr: 0x10,
                password: None,
                file_comment: None,
            },
        ];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.main.flags, 0x80);
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(archive.entries[0].name_lossy(), "README.md");
        assert_eq!(
            archive.entries[0].stored_data(&archive, None).unwrap(),
            b"hello rar 1.3"
        );
        assert!(archive.entries[1].is_directory());

        let extracted = archive.extract_stored(None).unwrap();
        assert_eq!(extracted[0].data, b"hello rar 1.3");
        assert!(extracted[1].is_directory);
    }

    #[test]
    fn rejects_malformed_main_header_boundaries() {
        assert_eq!(MainHeader::parse(b"RE~"), Err(Error::TooShort));

        let mut too_small = Vec::from(&b"RE~^"[..]);
        too_small.extend_from_slice(&6u16.to_le_bytes());
        too_small.push(0x80);
        assert_eq!(
            MainHeader::parse(&too_small),
            Err(Error::InvalidHeader(
                "RAR 1.3 main header is shorter than 7 bytes"
            ))
        );

        let mut truncated_extra = Vec::from(&b"RE~^"[..]);
        truncated_extra.extend_from_slice(&8u16.to_le_bytes());
        truncated_extra.push(0x80);
        assert_eq!(MainHeader::parse(&truncated_extra), Err(Error::TooShort));

        assert!(matches!(
            Archive::parse(b"Rar!\x1a\x07\x00"),
            Err(Error::UnsupportedSignature)
        ));
    }

    #[test]
    fn rejects_file_header_shorter_than_its_name() {
        let mut bytes = Vec::from(&b"RE~^"[..]);
        bytes.extend_from_slice(&7u16.to_le_bytes());
        bytes.push(0x80);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(FILE_HEAD_BASE_SIZE as u16).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(0x20);
        bytes.push(0);
        bytes.push(DEFAULT_UNP_VER);
        bytes.push(10);
        bytes.push(METHOD_STORE);

        assert!(matches!(
            Archive::parse(&bytes),
            Err(Error::InvalidHeader(
                "RAR 1.3 file header is shorter than its name"
            ))
        ));
    }

    #[test]
    fn rejects_truncated_file_payload_during_parse() {
        let input = [StoredEntry {
            name: b"hello.txt",
            data: b"hello",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];
        let mut bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        bytes.pop();

        assert!(matches!(Archive::parse(&bytes), Err(Error::TooShort)));
    }

    #[test]
    fn returns_none_for_absent_archive_comment() {
        let bytes = write_stored_archive(&[], WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        assert_eq!(archive.archive_comment().unwrap(), None);
    }

    #[test]
    fn rejects_normal_extract_on_split_entries() {
        let entry = StoredEntry {
            name: b"split.bin",
            data: b"abcdefghijklmnopqrstuvwxyz",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let volumes = write_stored_volumes(entry, WriterOptions::default(), 8).unwrap();
        let first = Archive::parse(&volumes[0]).unwrap();

        assert_eq!(
            first.extract(None),
            Err(Error::InvalidHeader(
                "RAR 1.3 split entry requires multivolume extraction"
            ))
        );
        assert_eq!(
            first.extract_stored(None),
            Err(Error::InvalidHeader(
                "RAR 1.3 split entry requires multivolume extraction"
            ))
        );
    }

    #[test]
    fn rejects_malformed_comment_extensions() {
        let packed_too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_COMMENT | MHD_PACK_COMMENT,
                head_size: MAIN_HEAD_SIZE,
                extra: 1u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
        };
        assert_eq!(
            packed_too_short.archive_comment(),
            Err(Error::InvalidHeader(
                "RAR 1.3 packed archive comment is shorter than size field"
            ))
        );

        let unpacked_too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_COMMENT,
                head_size: MAIN_HEAD_SIZE,
                extra: 4u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
        };
        assert_eq!(unpacked_too_short.archive_comment(), Err(Error::TooShort));
    }

    #[test]
    fn rejects_malformed_av_extensions() {
        let too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_AV,
                head_size: MAIN_HEAD_SIZE,
                extra: 5u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
        };
        assert_eq!(
            too_short.authenticity_verification(),
            Err(Error::InvalidHeader("RAR 1.3 AV payload is too short"))
        );

        let bad_prefix = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_AV,
                head_size: MAIN_HEAD_SIZE,
                extra: {
                    let mut extra = 6u16.to_le_bytes().to_vec();
                    extra.extend_from_slice(b"badbad");
                    extra
                },
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
        };
        assert_eq!(
            bad_prefix.authenticity_verification(),
            Err(Error::InvalidHeader("RAR 1.3 AV prefix mismatch"))
        );
    }

    #[test]
    fn writes_and_reads_encrypted_stored_archive() {
        let input = [StoredEntry {
            name: b"secret.txt",
            data: b"secret bytes",
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pass"),
            file_comment: None,
        }];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].is_encrypted());
        assert!(matches!(
            archive.entries[0].stored_data(&archive, None),
            Err(Error::NeedPassword)
        ));
        assert_eq!(
            archive.entries[0]
                .stored_data(&archive, Some(b"pass"))
                .unwrap(),
            b"secret bytes"
        );

        let extracted = archive.extract_stored(Some(b"pass")).unwrap();
        assert_eq!(extracted[0].data, b"secret bytes");
    }

    #[test]
    fn writes_and_reads_archive_comment() {
        let input = [StoredEntry {
            name: b"README.md",
            data: b"hello rar 1.3",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_stored_archive_with_comment(
            &input,
            WriterOptions::default(),
            Some(b"This is an archive comment."),
        )
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.main.has_archive_comment());
        assert!(archive.main.has_packed_comment());
        assert_eq!(
            archive.archive_comment().unwrap().as_deref(),
            Some(&b"This is an archive comment."[..])
        );
        assert_eq!(archive.extract(None).unwrap()[0].data, b"hello rar 1.3");
    }

    #[test]
    fn writes_and_reads_file_comment() {
        let input = [StoredEntry {
            name: b"README.md",
            data: b"hello rar 1.3",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: Some(b"file comment\r\n"),
        }];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].has_file_comment());
        assert_eq!(
            archive.entries[0].file_comment().unwrap().as_deref(),
            Some(&b"file comment\r\n"[..])
        );
        assert_eq!(archive.extract(None).unwrap()[0].data, b"hello rar 1.3");
    }

    #[test]
    fn writes_and_reads_literal_only_compressed_archive() {
        let input = [FileEntry {
            name: b"tiny.txt",
            data: b"literal bytes over sixteen",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.main.flags, 0x80);
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, b"tiny.txt");
        assert!(!archive.entries[0].is_stored());
        assert_eq!(archive.entries[0].header.method, 3);
        assert!(archive.entries[0].header.pack_size > 0);

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, b"literal bytes over sixteen");
    }

    #[test]
    fn writes_and_reads_literal_only_compressed_archive_with_repeated_stmode() {
        let data =
            b"this literal-only payload is long enough to enter and exit stmode more than once";
        let input = [FileEntry {
            name: b"long.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, 3);

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn compressed_writer_emits_short_lz_matches() {
        let data = b"abcabcabcabcabcabcabcabcabcabcabcabc";
        let input = [FileEntry {
            name: b"repeat.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, 3);
        assert!(
            archive.entries[0].header.pack_size < data.len() as u32,
            "ShortLZ should make the repeated payload smaller than stored data"
        );

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn compressed_writer_emits_long_lz_matches() {
        let mut data = short_lz_resistant_prefix(300);
        let repeated = data[..32].to_vec();
        data.extend_from_slice(&repeated);
        assert_eq!(
            find_long_lz(&data, 300),
            Some(LongLz {
                distance: 300,
                length: 18
            })
        );
        let input = [FileEntry {
            name: b"far.txt",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let literal_only = Unpack15Encoder::new()
            .encode_literals_only(&data)
            .unwrap()
            .len();
        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, 3);
        assert!(
            (archive.entries[0].header.pack_size as usize) < literal_only,
            "LongLZ should make a >256-byte-distance repeat smaller than literal-only output"
        );

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn writes_and_reads_solid_compressed_archive() {
        let input = [
            FileEntry {
                name: b"first.txt",
                data: b"first member primes the adaptive unpack15 state",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            FileEntry {
                name: b"second.txt",
                data: b"second member is encoded without resetting that state",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
        ];
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let options = WriterOptions {
            target: ArchiveVersion::Rar14,
            features,
        };

        let bytes = write_compressed_archive(&input, options).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.main.is_solid());
        assert_eq!(archive.entries.len(), 2);
        assert!(archive
            .entries
            .iter()
            .all(|entry| entry.header.flags & LHD_SOLID != 0));

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, input[0].data);
        assert_eq!(extracted[1].data, input[1].data);
    }

    #[test]
    fn writes_and_reads_encrypted_compressed_archive() {
        let input = [FileEntry {
            name: b"secret.txt",
            data: b"secret compressed bytes over sixteen",
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pass"),
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].is_encrypted());
        assert_eq!(archive.entries[0].header.method, 3);
        assert!(matches!(archive.extract(None), Err(Error::NeedPassword)));

        let extracted = archive.extract(Some(b"pass")).unwrap();
        assert_eq!(extracted[0].data, input[0].data);
    }

    #[test]
    fn writes_and_reads_compressed_file_comment() {
        let input = [FileEntry {
            name: b"commented.txt",
            data: b"compressed member with file comment",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: Some(b"compressed file comment"),
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(
            archive.entries[0].file_comment().unwrap().as_deref(),
            Some(&b"compressed file comment"[..])
        );

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, input[0].data);
    }

    #[test]
    fn writes_and_reads_stored_multivolume_archive() {
        let entry = StoredEntry {
            name: b"random.bin",
            data: b"abcdefghijklmnopqrstuvwxyz0123456789",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };

        let bytes = write_stored_volumes(entry, WriterOptions::default(), 10).unwrap();
        assert_eq!(bytes.len(), 4);
        let volumes: Vec<_> = bytes
            .iter()
            .map(|bytes| Archive::parse(bytes).unwrap())
            .collect();
        assert!(volumes.iter().all(|archive| archive.main.is_volume()));
        assert!(!volumes[0].entries[0].is_split_before());
        assert!(volumes[0].entries[0].is_split_after());
        assert!(volumes[1].entries[0].is_split_before());
        assert!(volumes[1].entries[0].is_split_after());
        assert!(volumes[3].entries[0].is_split_before());
        assert!(!volumes[3].entries[0].is_split_after());
        assert!(volumes.iter().all(|archive| archive.entries[0].is_stored()));

        let extracted = extract_volumes(&volumes, None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, b"random.bin");
        assert_eq!(extracted[0].data, entry.data);
    }

    #[test]
    fn writes_and_reads_compressed_multivolume_archive() {
        let data = b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
        let entry = FileEntry {
            name: b"repeat.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };

        let bytes = write_compressed_volumes(entry, WriterOptions::default(), 8).unwrap();
        assert!(bytes.len() >= 2);
        let volumes: Vec<_> = bytes
            .iter()
            .map(|bytes| Archive::parse(bytes).unwrap())
            .collect();
        assert!(volumes.iter().all(|archive| archive.main.is_volume()));
        assert!(!volumes[0].entries[0].is_stored());
        assert!(volumes[0].entries[0].is_split_after());
        assert!(volumes.last().unwrap().entries[0].is_split_before());
        assert!(!volumes.last().unwrap().entries[0].is_split_after());

        let extracted = extract_volumes(&volumes, None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, b"repeat.txt");
        assert_eq!(extracted[0].data, data);
    }

    fn short_lz_resistant_prefix(len: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            let next = (0u8..=u8::MAX)
                .find(|&candidate| {
                    if data.len() < 2 {
                        return true;
                    }
                    let start = data.len().saturating_sub(256);
                    !data[start..].windows(3).any(|window| {
                        window == [data[data.len() - 2], data[data.len() - 1], candidate]
                    })
                })
                .expect("byte alphabet can avoid local 3-byte repeats");
            data.push(next);
        }
        data
    }

    #[test]
    fn writes_empty_compressed_archive_member() {
        let input = [FileEntry {
            name: b"empty.bin",
            data: b"",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, 3);
        assert_eq!(archive.entries[0].header.pack_size, 0);

        let extracted = archive.extract(None).unwrap();
        assert_eq!(extracted[0].data, b"");
    }

    #[test]
    fn rejects_rar5_only_features_for_rar13() {
        let mut features = FeatureSet::store_only();
        features.quick_open = true;

        let options = WriterOptions {
            target: ArchiveVersion::Rar13,
            features,
        };
        let err = write_stored_archive(&[], options).unwrap_err();
        assert_eq!(
            err,
            Error::UnsupportedFeature {
                version: ArchiveVersion::Rar13,
                feature: "quick_open"
            }
        );
    }

    #[test]
    fn rejects_unimplemented_rar13_writer_features() {
        let mut features = FeatureSet::store_only();
        features.sfx = true;

        let options = WriterOptions {
            target: ArchiveVersion::Rar14,
            features,
        };
        let err = write_stored_archive(&[], options).unwrap_err();
        assert_eq!(
            err,
            Error::UnsupportedFeature {
                version: ArchiveVersion::Rar14,
                feature: "sfx"
            }
        );
    }

    #[test]
    fn file_checksum_matches_rar13_algorithm() {
        assert_eq!(file_checksum(b""), 0x0000);
        assert_eq!(file_checksum(b"123456789"), 0xc78a);
    }
}
