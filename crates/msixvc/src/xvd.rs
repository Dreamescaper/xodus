use std::cmp::min;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{self, Error, ErrorKind, Read, Seek, SeekFrom, Write};

use aes::cipher::KeyInit;
use aes::{Aes128Dec, Aes128Enc};
use futures_util::StreamExt;
use msixvc_common::parse::{BinaryParse, BinaryTryParse};
use reqwest::header::RANGE;
use tokio::fs::OpenOptions;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::task::block_in_place;
use tokio::time::{sleep, timeout};
use tokio_util::io::SyncIoBridge;
use uuid::Uuid;
use zerocopy::IntoBytes;

use crate::crypt::{TweakGenerator, decrypt_page_xts};
use crate::layout::{Bytes, PAGE_SIZE, PAGES_PER_BLOCK, Pages};
use crate::math::calculate_hash_block_num_and_run_for_block_num;
use crate::models::xvd::layout::XvdLayout;
use crate::models::xvd::{
    XvcInfo, XvcRegionHeader, XvcRegionId, XvdHashEntry, XvdHeader, XvdSegmentMetadataHeader,
    XvdSegmentMetadataSegment, XvdSegmentMetadataSegmentFlags, XvdUserDataHeader,
    XvdUserDataPackageFileEntry, XvdUserDataPackageFilesHeader,
};
use crate::streaming_ntfs::collect_ntfs_stream_layouts;

const MAX_RECONNECT_ATTEMPTS: usize = 5;

#[cfg(not(test))]
const RECONNECT_INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(test)]
const RECONNECT_INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_millis(5);

fn reconnect_backoff(attempt: usize) -> std::time::Duration {
    RECONNECT_INITIAL_BACKOFF * 2u32.pow(attempt as u32)
}

pub struct SyncSubstream<R> {
    inner: R,
    start: u64,
    len: u64,
    pos: u64,
}

impl<R> Debug for SyncSubstream<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncSubstream")
            .field("start", &self.start)
            .field("len", &self.len)
            .field("pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl<R> SyncSubstream<R> {
    pub fn new(inner: R, start: u64, len: u64) -> Self {
        Self {
            inner,
            start,
            len,
            pos: 0,
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

impl<R: Read + Seek> Read for SyncSubstream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }

        let remaining = usize::try_from(self.len - self.pos)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "remaining range too large"))?;
        let to_read = remaining.min(buf.len());

        self.inner.seek(SeekFrom::Start(self.start + self.pos))?;
        let read = self.inner.read(&mut buf[..to_read])?;
        self.pos += read as u64;
        Ok(read)
    }
}

impl<R: Seek> Seek for SyncSubstream<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.pos.checked_add(delta as u64).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "invalid relative seek")
                    })?
                } else {
                    self.pos.checked_sub(delta.unsigned_abs()).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "invalid relative seek")
                    })?
                }
            }
            SeekFrom::End(delta) => {
                if delta >= 0 {
                    self.len.checked_add(delta as u64).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "invalid end-relative seek")
                    })?
                } else {
                    self.len.checked_sub(delta.unsigned_abs()).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "invalid end-relative seek")
                    })?
                }
            }
        };

        if next > self.len {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "seek past substream end",
            ));
        }

        self.pos = next;
        Ok(self.pos)
    }
}

impl<R: Write + Seek> Write for SyncSubstream<R> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }

        let remaining = usize::try_from(self.len - self.pos)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "remaining range too large"))?;
        let to_write = remaining.min(buf.len());

        self.inner.seek(SeekFrom::Start(self.start + self.pos))?;
        let written = self.inner.write(&buf[..to_write])?;
        self.pos += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct XvdEncryptionInfo {
    encrypted_sections: Vec<EncryptedSectionInfo>,
}

// The gpt crate requires the device to implement Debug,
// but the content key must not be debuged
impl Debug for XvdEncryptionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XvdEncryptionInfo")
            .field("encrypted_sections", &self.encrypted_sections)
            .finish_non_exhaustive() // prints ", .." to signal redacted fields
    }
}

struct XvdStream<R> {
    inner: R,
    offset: u64,
    end_offset: u64,

    encryption_info: Option<XvdEncryptionInfo>,
}

impl<R> Debug for XvdStream<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XvdStream")
            .field("offset", &self.offset)
            .field("end_offset", &self.end_offset)
            .field("encryption_info", &self.encryption_info)
            .finish_non_exhaustive()
    }
}

impl<R> XvdStream<R> {
    fn len(&self) -> u64 {
        self.end_offset - self.offset
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Seek> XvdStream<R> {
    fn current_relative_pos(&mut self) -> std::io::Result<u64> {
        let absolute = self.inner.stream_position()?;
        absolute
            .checked_sub(self.offset)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "stream before virtual start"))
    }
}

impl<R: Read + Seek> Read for XvdStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let current = self.current_relative_pos()?;
        if current >= self.len() {
            return Ok(0);
        }

        let remaining = usize::try_from(self.len() - current)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "remaining range too large"))?;
        let to_read = remaining.min(buf.len());

        self.inner.read(&mut buf[..to_read])
    }
}

impl<R: Seek> Seek for XvdStream<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_relative = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(delta) => {
                let current = self.current_relative_pos()?;
                if delta >= 0 {
                    current.checked_add(delta as u64)
                } else {
                    current.checked_sub(delta.unsigned_abs())
                }
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid relative seek"))?
            }
            SeekFrom::End(delta) => {
                let len = self.len();
                if delta >= 0 {
                    len.checked_add(delta as u64)
                } else {
                    len.checked_sub(delta.unsigned_abs())
                }
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid end-relative seek"))?
            }
        };

        if new_relative > self.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "seek past virtual device end",
            ));
        }

        self.inner
            .seek(SeekFrom::Start(self.offset + new_relative))?;
        Ok(new_relative)
    }
}

impl<R> Write for XvdStream<R> {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(Error::new(
            ErrorKind::PermissionDenied,
            "XvdStream is read-only",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub struct XvdFile {
    header: XvdHeader,
    layout: XvdLayout,
    encrypted_section_infos: Vec<EncryptedSectionInfo>,
}

#[derive(Debug)]
pub struct EncryptedSectionInfo {
    section_offset: u64,
    section_length: u64,

    header_id: XvcRegionId,
    vduid: Uuid,

    // If integrity is enabled, this must contain one entry per page in the section.
    // If integrity is disabled, use page_in_section as the data unit instead.
    data_units: Option<Vec<u32>>,
    first_segment_index: u32,
    data_hashs: Vec<[u8; 20]>,
}

pub struct UserPackageFile {
    pub offset: u64,
    pub length: u64,
}

pub struct SegmentFile {
    pub offset: u64,
    pub length: u64,
    pub data_hashs: Vec<[u8; 20]>,
    pub keep_encrypted: bool,
}

impl SegmentFile {
    /// Ciphertext is retained as complete XTS data units, including the final
    /// page beyond the logical file length. Plain files have no such padding.
    pub fn stored_length(&self) -> io::Result<u64> {
        if !self.keep_encrypted {
            return Ok(self.length);
        }
        self.length
            .div_ceil(PAGE_SIZE as u64)
            .checked_mul(PAGE_SIZE as u64)
            .ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "encrypted file length overflows")
            })
    }
}

fn decode_utf16(bytes: &[u16], what: &str) -> io::Result<String> {
    String::from_utf16(bytes).map_err(|err| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("invalid UTF-16 in {what}: {err}"),
        )
    })
}

type SegmentByteStream = std::pin::Pin<
    Box<dyn futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send>,
>;

async fn open_segment_stream(
    client: &reqwest::Client,
    url: &str,
    start: u64,
    end: u64,
    stall_timeout: tokio::time::Duration,
) -> Option<SegmentByteStream> {
    match timeout(
        stall_timeout,
        client
            .get(url)
            .header(RANGE, format!("bytes={start}-{end}"))
            .send(),
    )
    .await
    .map(|o| o.map(|o| o.error_for_status()))
    {
        Ok(Ok(Ok(response))) if response.status() == 206 => Some(Box::pin(response.bytes_stream())),
        _ => None,
    }
}

impl XvdFile {
    pub fn content_id(&self) -> uuid::Uuid {
        self.header.vduid
    }

    pub fn resume_identity(&self) -> String {
        let mut identity = self.header.signature.to_vec();
        identity.extend(self.header.top_hash_block_hash);
        identity.extend(self.header.original_xvc_data_hash);
        identity.extend(self.header.user_data_hash);
        identity.extend(self.header.vduid.as_bytes());
        identity.extend(self.header.pduid.as_bytes());
        crate::streaming::resume_digest(&identity)
    }

    fn non_encrypted_prefix_len(&self, start: u64, len: u64) -> u64 {
        let end = start.saturating_add(len);
        let mut prefix_len = len;

        for section in &self.encrypted_section_infos {
            let section_start = section.section_offset;
            let section_end = section
                .section_offset
                .saturating_add(section.section_length);

            if section_end <= start || section_start >= end {
                continue;
            }

            if start >= section_start {
                return 0;
            }

            prefix_len = section_start.saturating_sub(start);
            break;
        }

        prefix_len
    }

    pub async fn parse_file(path: String) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new().read(true).open(path.clone()).await?;
        Self::parse(&mut file).await
    }

    pub async fn parse<Reader>(mut file: Reader) -> Result<Self, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let xvd_header = {
            let mut buf = XvdHeader::buffer();
            file.read_exact(&mut buf).await?;
            XvdHeader::try_from_array(&buf)?
        };

        let layout = xvd_header.layout()?;

        let mut region_headers: Vec<XvcRegionHeader> = Vec::new();

        // TODO: Check if we have proper content type
        if layout.xvc_info.len > Bytes(0) {
            file.seek(std::io::SeekFrom::Start(layout.xvc_info.start.to_bytes().0))
                .await?;

            let xvc_info = {
                let mut buf = XvcInfo::buffer();
                file.read_exact(&mut buf).await?;
                XvcInfo::from_array(&buf)
            };

            let region_count = xvc_info.region_count;

            if xvc_info.version >= 1 {
                let mut buf = XvcRegionHeader::buffer();
                for _ in 0..region_count {
                    file.read_exact(&mut buf).await?;
                    let region_header = XvcRegionHeader::try_from_array(&buf)?;
                    region_headers.push(region_header);
                }
            }
        }

        let hash_tree_levels =
            layout.hash_tree_layout.top_level().ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "missing hash tree top level")
            })? as u64
                + 1;

        let mut enc_sections: Vec<EncryptedSectionInfo> = vec![];
        let mut reader = BufReader::with_capacity(PAGES_PER_BLOCK * XvdHashEntry::SIZE, file);
        for h in region_headers {
            let key_id = h.key_id;
            let num_pages = h.length.0;
            match key_id.get() {
                None => continue,
                Some(0) => (),
                Some(n) => {
                    return Err(io::Error::new(
                        ErrorKind::Unsupported,
                        format!(
                            "key id {n} is not supported (only key id 0 or unencrypted regions are)"
                        ),
                    )
                    .into());
                }
            }

            let start_page = h
                .offset
                .0
                .checked_sub(layout.user_data.start.0)
                .ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        "region starts before user data section",
                    )
                })?;
            let start_page = Pages(start_page);
            let mut data_units: Vec<u32> = Vec::with_capacity(num_pages as usize);
            let mut data_hashs: Vec<[u8; 20]> = Vec::with_capacity(num_pages as usize);

            let mut page = 0;
            loop {
                if page >= num_pages {
                    break;
                }
                let block_num = start_page.0.checked_add(page).ok_or_else(|| {
                    io::Error::new(ErrorKind::InvalidData, "region page index overflow")
                })?;
                let (hash_block, entry_start, run_length) =
                    calculate_hash_block_num_and_run_for_block_num(
                        xvd_header.xvd_type as u32,
                        hash_tree_levels,
                        xvd_header.number_of_hashed_pages(),
                        block_num,
                        0,
                        false,
                        false,
                    );
                let run_length = min(run_length, num_pages - page);
                page += run_length;
                let read_offset = layout.hash_tree.start.to_bytes()
                    + Pages(hash_block).to_bytes()
                    + Bytes(entry_start as u64 * XvdHashEntry::SIZE as u64);
                reader.seek(SeekFrom::Start(read_offset.0)).await?;

                let mut buf = XvdHashEntry::buffer();
                for _ in 0..run_length {
                    reader.read_exact(&mut buf).await?;
                    let hash = XvdHashEntry::from_array(&buf);
                    data_units.push(hash.unit);
                    data_hashs.push(hash.block_hash);
                }
            }

            enc_sections.push(EncryptedSectionInfo {
                section_offset: h.offset.to_bytes().0,
                section_length: h.length.to_bytes().0,
                header_id: h.region_id,
                vduid: xvd_header.vduid,
                data_units: Some(data_units),
                first_segment_index: h.first_segment_index,
                data_hashs,
            });
        }
        Ok(XvdFile {
            header: xvd_header,
            layout,
            encrypted_section_infos: enc_sections,
        })
    }

    pub async fn parse_user_package_files<Reader>(
        &self,
        mut file: Reader,
    ) -> Result<HashMap<String, UserPackageFile>, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let mut files = HashMap::new();

        let user_data_offset = self.layout.user_data.start.0 as u64;
        file.seek(SeekFrom::Start(user_data_offset)).await?;
        let user_data_header = {
            let mut buf = XvdUserDataHeader::buffer();
            file.read_exact(&mut buf).await?;
            XvdUserDataHeader::from_array(&buf)
        };
        if user_data_header.t == 0 {
            let mut off = user_data_offset + user_data_header.length as u64;
            file.seek(SeekFrom::Start(off)).await?;
            let user_data_package_files_header = {
                let mut buf = XvdUserDataPackageFilesHeader::buffer();
                file.read_exact(&mut buf).await?;
                XvdUserDataPackageFilesHeader::from_array(&buf)
            };
            off += XvdUserDataPackageFilesHeader::SIZE as u64;
            let mut buf = XvdUserDataPackageFileEntry::buffer();
            for _ in 0..user_data_package_files_header.file_count {
                file.seek(SeekFrom::Start(off)).await?;
                file.read_exact(&mut buf).await?;
                let user_data_package_file_entry = XvdUserDataPackageFileEntry::from_array(&buf);
                off += XvdUserDataPackageFileEntry::SIZE as u64;
                let o = user_data_package_file_entry.offset;
                let s: u32 = user_data_package_file_entry.size;
                let fullname = user_data_package_file_entry.file_path;
                let end = fullname
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(fullname.len());
                let pfull_name = decode_utf16(&fullname[..end], "package file path")?;

                files.insert(
                    pfull_name,
                    UserPackageFile {
                        offset: user_data_offset + XvdUserDataHeader::SIZE as u64 + o as u64,
                        length: s as u64,
                    },
                );
            }
        }
        Ok(files)
    }

    pub async fn parse_segment_metadata<Reader>(
        &self,
        file: Reader,
        segment_metadata: &UserPackageFile,
    ) -> Result<HashMap<String, SegmentFile>, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let mut file = BufReader::with_capacity(segment_metadata.length as usize, file);
        file.seek(SeekFrom::Start(segment_metadata.offset)).await?;
        let segment_header = {
            let mut buf = XvdSegmentMetadataHeader::buffer();
            file.read_exact(&mut buf).await?;
            XvdSegmentMetadataHeader::try_from_array(&buf)?
        };
        let paths_offset =
            segment_header.header_length as u64 + segment_header.segment_count as u64 * 0x10;

        let mut segments = Vec::with_capacity(segment_header.segment_count as usize);
        let mut buf = XvdSegmentMetadataSegment::buffer();
        for _ in 0..segment_header.segment_count {
            file.read_exact(&mut buf).await?;
            let segment = XvdSegmentMetadataSegment::from_array(&buf);
            segments.push(segment);
        }

        let mut files = HashMap::new();

        for section in &self.encrypted_section_infos {
            let segment_page_start = section.section_offset.div_ceil(PAGE_SIZE as u64);
            let mut page_offset = segment_page_start;
            for segment_no in section.first_segment_index..segment_header.segment_count {
                let segment = segments.get(segment_no as usize).ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "segment index {segment_no} is out of range for {} segments",
                            segments.len()
                        ),
                    )
                })?;
                let s = segment.path_length;
                let mut buf = vec![0u16, 0];
                buf.resize(s as usize, 0);
                let path_start = segment_metadata
                    .offset
                    .checked_add(paths_offset)
                    .and_then(|offset| offset.checked_add(segment.path_offset as u64))
                    .ok_or_else(|| {
                        io::Error::new(ErrorKind::InvalidData, "segment path offset overflow")
                    })?;
                file.seek(SeekFrom::Start(path_start)).await?;
                file.read_exact(buf.as_mut_bytes()).await?;
                let file_name = decode_utf16(buf.as_slice(), "segment file path")?;
                let page_length = if segment.filesize == 0 {
                    1
                } else {
                    segment.filesize.div_ceil(PAGE_SIZE as u64)
                };
                let page_byte_offset = page_offset.saturating_mul(PAGE_SIZE as u64);
                if page_byte_offset
                    >= section
                        .section_offset
                        .saturating_add(section.section_length)
                {
                    break;
                }
                let relative_start =
                    page_offset.checked_sub(segment_page_start).ok_or_else(|| {
                        io::Error::new(
                            ErrorKind::InvalidData,
                            "segment page offset starts before its section",
                        )
                    })?;
                let start = usize::try_from(relative_start).map_err(|_| {
                    io::Error::new(ErrorKind::InvalidData, "segment page offset is too large")
                })?;
                let page_count = usize::try_from(segment.filesize.div_ceil(PAGE_SIZE as u64))
                    .map_err(|_| {
                        io::Error::new(ErrorKind::InvalidData, "segment page count is too large")
                    })?;
                let end = start.checked_add(page_count).ok_or_else(|| {
                    io::Error::new(ErrorKind::InvalidData, "segment page range overflow")
                })?;
                let data_hashs: Vec<[u8; 20]> = section
                    .data_hashs
                    .get(start..end)
                    .ok_or_else(|| {
                        io::Error::new(
                            ErrorKind::InvalidData,
                            format!(
                                "missing data hashes for {file_name}: need [{start}..{end}], have {}",
                                section.data_hashs.len()
                            ),
                        )
                    })?
                    .into();
                files.insert(
                    file_name,
                    SegmentFile {
                        offset: page_offset.checked_mul(PAGE_SIZE as u64).ok_or_else(|| {
                            io::Error::new(ErrorKind::InvalidData, "segment offset overflow")
                        })?,
                        length: segment.filesize,
                        data_hashs,
                        keep_encrypted: segment
                            .flags
                            .contains(XvdSegmentMetadataSegmentFlags::KEEP_ENCRYPTED_ON_DISK),
                    },
                );
                page_offset = page_offset.saturating_add(page_length);
            }
        }
        Ok(files)
    }

    pub fn populate_segment_hashes(
        &self,
        files: &mut HashMap<String, SegmentFile>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (name, file) in files.iter_mut() {
            if !file.data_hashs.is_empty() {
                continue;
            }

            let Some(section) = self.encrypted_section_infos.iter().find(|section| {
                file.offset >= section.section_offset
                    && file.offset
                        < section
                            .section_offset
                            .saturating_add(section.section_length)
            }) else {
                continue;
            };

            let file_end = file.offset.saturating_add(file.length);
            let section_end = section
                .section_offset
                .saturating_add(section.section_length);
            if file_end > section_end {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "segment file spans beyond encrypted section: {} ({}..{} > {}..{})",
                        name, file.offset, file_end, section.section_offset, section_end
                    ),
                )
                .into());
            }

            let segment_page_start = section.section_offset.div_ceil(PAGE_SIZE as u64);
            let page_offset = file.offset.div_ceil(PAGE_SIZE as u64);
            let page_count =
                usize::try_from(file.length.div_ceil(PAGE_SIZE as u64)).map_err(|_| {
                    io::Error::new(
                        ErrorKind::InvalidInput,
                        format!("segment page count is too large: {name}"),
                    )
                })?;
            let start =
                usize::try_from(page_offset.checked_sub(segment_page_start).ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "segment page offset before section start: {} ({})",
                            name, file.offset
                        ),
                    )
                })?)
                .map_err(|_| {
                    io::Error::new(
                        ErrorKind::InvalidInput,
                        format!("segment page offset is too large: {name}"),
                    )
                })?;
            let end = start.checked_add(page_count).ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("segment page range overflow: {name}"),
                )
            })?;

            let data_hashs = section.data_hashs.get(start..end).ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "missing data hashes for {}: need [{}..{}], have {}",
                        name,
                        start,
                        end,
                        section.data_hashs.len()
                    ),
                )
            })?;

            file.data_hashs = data_hashs.into();
        }

        Ok(())
    }

    pub async fn parse_ntfs_segment_metadata<Reader>(
        &self,
        file: Reader,
        only_plain: bool,
    ) -> Result<HashMap<String, SegmentFile>, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let drive_data_offset = self.layout.drive_data.start.to_bytes().0;
        let drive_size = self.header.drive_size;
        let drive_plain_len = self.non_encrypted_prefix_len(drive_data_offset, drive_size.0);

        block_in_place(|| {
            let block_size = 4096;
            let drive = SyncSubstream::new(
                XvdStream {
                    inner: SyncIoBridge::new(file),
                    offset: drive_data_offset,
                    end_offset: drive_data_offset.saturating_add(drive_plain_len),
                    encryption_info: None,
                },
                0,
                drive_plain_len,
            );

            let logical_block_size = match block_size {
                512 => gpt::disk::LogicalBlockSize::Lb512,
                4096 => gpt::disk::LogicalBlockSize::Lb4096,
                _ => {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        format!("unsupported block size: {block_size}"),
                    )
                    .into());
                }
            };
            let gp = gpt::GptConfig::new()
                .writable(false)
                .logical_block_size(logical_block_size)
                .open_from_device(drive)?;

            let (_, part) = gp
                .partitions()
                .iter()
                .find(|(_, part)| part.is_used())
                .ok_or_else(|| {
                    io::Error::new(ErrorKind::NotFound, "no used GPT partition found")
                })?;

            let part_start = part
                .bytes_start(*gp.logical_block_size())
                .map_err(|err| io::Error::other(format!("invalid GPT partition start: {err}")))?;
            let part_len = part
                .bytes_len(*gp.logical_block_size())
                .map_err(|err| io::Error::other(format!("invalid GPT partition length: {err}")))?;

            let bridge = gp.take_device().into_inner().into_inner();
            let partition_offset = drive_data_offset.saturating_add(part_start);
            let partition_plain_len = self.non_encrypted_prefix_len(partition_offset, part_len);
            let mut fs = SyncSubstream::new(
                XvdStream {
                    inner: bridge,
                    offset: partition_offset,
                    end_offset: partition_offset.saturating_add(partition_plain_len),
                    encryption_info: None,
                },
                0,
                partition_plain_len,
            );

            let reports = collect_ntfs_stream_layouts(&mut fs)?;
            let mut files = HashMap::new();

            for report in reports {
                if report.path.starts_with('$') || report.path.contains(':') {
                    continue;
                }
                if report.resident_data || report.data_runs.len() != 1 {
                    continue;
                }

                let Some(data_run) = report.data_runs.first() else {
                    continue;
                };
                let Some(start) = data_run.start else {
                    continue;
                };

                if only_plain
                    && partition_offset.saturating_add(start)
                        >= drive_data_offset.saturating_add(drive_plain_len)
                {
                    continue;
                }

                files.insert(
                    report.path.replace("/", "\\"),
                    SegmentFile {
                        offset: partition_offset.saturating_add(start),
                        length: report.value_length,
                        data_hashs: vec![],
                        keep_encrypted: !only_plain
                            && report.path.to_ascii_lowercase().ends_with(".exe"),
                    },
                );
            }

            self.populate_segment_hashes(&mut files)?;

            Ok(files)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn download_file_http<Writer, Progress, Checkpoint>(
        &self,
        client: &reqwest::Client,
        urls: &[String],
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        mut progress: Progress,
        resume_offset: u64,
        mut checkpoint: Checkpoint,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
        Checkpoint: FnMut(u64) -> std::io::Result<()>,
    {
        if urls.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "no package download URL was provided",
            )
            .into());
        }
        if sfile.length == 0 {
            return Ok(());
        }

        let s = self.encrypted_section_infos.iter().find(|s| {
            sfile.offset >= s.section_offset
                && sfile.offset < s.section_offset.saturating_add(s.section_length)
        });

        let mut tweak = None;
        let mut tweak_cipher = None;
        let mut data_cipher = None;

        let file_offset_in_section;

        if let Some(s) = s
            && !sfile.keep_encrypted
        {
            let mut tweak_key = [0u8; 16];
            let mut data_key = [0u8; 16];
            tweak_key.copy_from_slice(&full_key[..16]);
            data_key.copy_from_slice(&full_key[16..]);

            tweak = Some(TweakGenerator::new(s.header_id, s.vduid));
            tweak_cipher = Some(Aes128Enc::new((&tweak_key).into()));
            data_cipher = Some(Aes128Dec::new((&data_key).into()));
            file_offset_in_section = sfile.offset - s.section_offset;
        } else {
            // TODO for data integrity we need a section for unencrypted sections...
            file_offset_in_section = sfile.offset;
        }
        let page_start = file_offset_in_section / PAGE_SIZE as u64;
        let page_count = sfile.length.div_ceil(PAGE_SIZE as u64);

        if resume_offset > sfile.length || !resume_offset.is_multiple_of(PAGE_SIZE as u64) {
            return Err(
                io::Error::new(ErrorKind::InvalidInput, "invalid download resume offset").into(),
            );
        }

        let mut page = [0u8; PAGE_SIZE];
        let mut remaining = sfile.length - resume_offset;
        let mut page_in_section = page_start + resume_offset / PAGE_SIZE as u64;
        let page_length = sfile
            .length
            .div_ceil(PAGE_SIZE as u64)
            .saturating_mul(PAGE_SIZE as u64);
        let mut pending = bytes::BytesMut::new();
        let mut v: u64 = resume_offset;
        let mut last_checkpoint = resume_offset;

        let stall_timeout = tokio::time::Duration::from_secs(5);
        let mut reconnect_attempts = 0usize;
        let mut url_index = 0usize;
        let mut stream = open_segment_stream(
            client,
            &urls[url_index],
            sfile.offset + v,
            sfile.offset + page_length - 1,
            stall_timeout,
        )
        .await;
        loop {
            if page_in_section >= page_start + page_count || remaining == 0 {
                break;
            }
            let next = if let Some(s) = stream.as_mut() {
                timeout(stall_timeout, s.next()).await
            } else {
                Ok(None)
            };
            let data = match next {
                Ok(Some(Ok(data))) if !data.is_empty() => data,
                _ => {
                    if reconnect_attempts >= MAX_RECONNECT_ATTEMPTS {
                        out.flush().await?;
                        checkpoint(sfile.length - remaining)?;
                        if url_index + 1 < urls.len() {
                            url_index += 1;
                            reconnect_attempts = 0;
                            stream = open_segment_stream(
                                client,
                                &urls[url_index],
                                sfile.offset + v,
                                sfile.offset + page_length - 1,
                                stall_timeout,
                            )
                            .await;
                            continue;
                        }
                        return Err(io::Error::other(format!(
                            "download interrupted for segment at offset {} (length {}): {} reconnect attempts failed on {} hosts ({} of {} bytes received)",
                            sfile.offset,
                            sfile.length,
                            reconnect_attempts,
                            urls.len(),
                            v,
                            sfile.length
                        ))
                        .into());
                    }
                    let backoff = reconnect_backoff(reconnect_attempts);
                    reconnect_attempts += 1;
                    sleep(backoff).await;
                    stream = open_segment_stream(
                        client,
                        &urls[url_index],
                        sfile.offset + v,
                        sfile.offset + page_length - 1,
                        stall_timeout,
                    )
                    .await;
                    continue;
                }
            };

            reconnect_attempts = 0;
            v += data.len() as u64;
            progress(min(v, sfile.length), sfile.length);

            pending.extend_from_slice(&data);

            while pending.len() >= 4096 {
                if page_in_section >= page_start + page_count || remaining == 0 {
                    break;
                }
                let chunk = pending.split_to(4096);
                page.copy_from_slice(&chunk);
                let to_write_remaining = remaining.min(PAGE_SIZE as u64) as usize;
                let to_write = if let Some(tweak) = &tweak {
                    let section = s.ok_or_else(|| {
                        io::Error::new(
                            ErrorKind::InvalidData,
                            "missing encrypted section for the segment",
                        )
                    })?;
                    let tweak = tweak.with_data_unit(match &section.data_units {
                        Some(units) => *units.get(page_in_section as usize).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!(
                                    "{} units {} page_in_section {} ({}+{})",
                                    "missing data unit",
                                    (*units).len(),
                                    page_in_section,
                                    page_start,
                                    page_count
                                ),
                            )
                        })?,
                        None => page_in_section as u32,
                    });
                    let tweak_cipher = tweak_cipher.as_ref().ok_or_else(|| {
                        io::Error::new(ErrorKind::InvalidData, "missing tweak cipher")
                    })?;
                    let data_cipher = data_cipher.as_ref().ok_or_else(|| {
                        io::Error::new(ErrorKind::InvalidData, "missing data cipher")
                    })?;
                    decrypt_page_xts(&mut page, tweak, tweak_cipher, data_cipher);
                    to_write_remaining
                } else if sfile.keep_encrypted {
                    // Decryption needs full 4k blocks
                    PAGE_SIZE
                } else {
                    to_write_remaining
                };
                out.write_all(&page[..to_write]).await.map_err(|err| {
                    io::Error::other(format!(
                        "failed to write segment at offset {} ({} bytes): {err}",
                        sfile.offset, sfile.length
                    ))
                })?;
                remaining -= to_write_remaining as u64;

                page_in_section += 1;
            }

            let written = sfile.length - remaining;
            if written.saturating_sub(last_checkpoint) >= 32 * 1024 * 1024 {
                out.flush().await?;
                checkpoint(written)?;
                last_checkpoint = written;
            }
        }
        if remaining > 0 {
            out.flush().await?;
            checkpoint(sfile.length - remaining)?;
            return Err(Box::new(std::io::Error::other(format!(
                "{} of {} missing have {}",
                remaining, sfile.length, v
            ))));
        }
        out.flush().await?;
        checkpoint(sfile.length)?;
        Ok(())
    }

    async fn extract_file_ex<Writer, Reader, Progress>(
        &self,
        i: &mut Reader,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        mut progress: Progress,
        decrypt_all: bool,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + Unpin,
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        if sfile.length == 0 {
            return Ok(());
        }

        let s = self.encrypted_section_infos.iter().find(|s| {
            sfile.offset >= s.section_offset
                && sfile.offset < s.section_offset.saturating_add(s.section_length)
        });

        let mut tweak = None;
        let mut tweak_cipher = None;
        let mut data_cipher = None;

        let file_offset_in_section;

        if let Some(s) = s
            && (!sfile.keep_encrypted || decrypt_all)
        {
            let mut tweak_key = [0u8; 16];
            let mut data_key = [0u8; 16];
            tweak_key.copy_from_slice(&full_key[..16]);
            data_key.copy_from_slice(&full_key[16..]);

            tweak = Some(TweakGenerator::new(s.header_id, s.vduid));
            tweak_cipher = Some(Aes128Enc::new((&tweak_key).into()));
            data_cipher = Some(Aes128Dec::new((&data_key).into()));
            file_offset_in_section = sfile.offset - s.section_offset;
        } else {
            // TODO for data integrity we need a section for unencrypted sections...
            file_offset_in_section = sfile.offset;
        }
        let page_start = file_offset_in_section / PAGE_SIZE as u64;
        let page_count = sfile.length.div_ceil(PAGE_SIZE as u64);

        let mut page = [0u8; PAGE_SIZE];

        for page_in_section in page_start..page_start + page_count {
            progress(
                min((page_in_section - page_start) * 4096, sfile.length),
                sfile.length,
            );
            i.read_exact(&mut page).await?;
            let to_write = min(
                PAGE_SIZE,
                sfile.length as usize
                    - min(
                        (page_in_section - page_start) as usize * 4096_usize,
                        sfile.length as usize,
                    ),
            ) as usize;
            let to_write = if let Some(tweak) = &tweak {
                let section = s.ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        "missing encrypted section for the segment",
                    )
                })?;
                let tweak = tweak.with_data_unit(match &section.data_units {
                    Some(units) => *units.get(page_in_section as usize).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "{} units {} page_in_section {} ({}+{})",
                                "missing data unit",
                                (*units).len(),
                                page_in_section,
                                page_start,
                                page_count
                            ),
                        )
                    })?,
                    None => page_in_section as u32,
                });
                let tweak_cipher = tweak_cipher.as_ref().ok_or_else(|| {
                    io::Error::new(ErrorKind::InvalidData, "missing tweak cipher")
                })?;
                let data_cipher = data_cipher
                    .as_ref()
                    .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "missing data cipher"))?;
                decrypt_page_xts(&mut page, tweak, tweak_cipher, data_cipher);
                to_write
            } else if sfile.keep_encrypted {
                // Decryption needs full 4k blocks
                PAGE_SIZE
            } else {
                to_write
            };
            out.write_all(&page[..to_write]).await.map_err(|err| {
                io::Error::other(format!(
                    "failed to write segment at offset {} ({} bytes): {err}",
                    sfile.offset, sfile.length
                ))
            })?;
        }
        Ok(())
    }

    // Reader is an full xvd file
    pub async fn extract_file<Writer, Reader, Progress>(
        &self,
        i: &mut Reader,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        progress: Progress,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        i.seek(std::io::SeekFrom::Start(sfile.offset)).await?;
        self.extract_file_ex(i, out, sfile, full_key, progress, false)
            .await
    }

    // Reader points to file content
    pub async fn mount_mem_fd<Writer, Reader, Progress>(
        &self,
        i: &mut Reader,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        progress: Progress,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + Unpin,
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        self.extract_file_ex(i, out, sfile, full_key, progress, true)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    enum ServerMode {
        NotFound,
        DropFirstThenServe(Vec<u8>),
    }

    async fn spawn_server(mode: ServerMode) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut connection = 0usize;
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while let Ok(1) = socket.read(&mut byte).await {
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }

                let current = connection;
                connection += 1;
                match &mode {
                    ServerMode::NotFound => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                    ServerMode::DropFirstThenServe(_) if current == 0 => {}
                    ServerMode::DropFirstThenServe(body) => {
                        let length = body.len();
                        let headers = format!(
                            "HTTP/1.1 206 Partial Content\r\nContent-Length: {length}\r\nContent-Range: bytes 0-{}/{length}\r\nConnection: close\r\n\r\n",
                            length.saturating_sub(1)
                        );
                        let _ = socket.write_all(headers.as_bytes()).await;
                        let _ = socket.write_all(body).await;
                    }
                }
                let _ = socket.shutdown().await;
            }
        });
        (address, handle)
    }

    fn test_xvd() -> XvdFile {
        let mut header = XvdHeader::buffer();
        header[0x200..0x208].copy_from_slice(b"msft-xvd");
        header[0x210..0x218].copy_from_slice(&116_444_736_000_000_000i64.to_le_bytes());
        header[0x218..0x220].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
        let header = XvdHeader::try_from_array(&header).unwrap();
        let layout = header.layout().unwrap();
        XvdFile {
            header,
            layout,
            encrypted_section_infos: vec![],
        }
    }

    fn test_segment() -> SegmentFile {
        SegmentFile {
            offset: 0,
            length: PAGE_SIZE as u64,
            data_hashs: vec![],
            keep_encrypted: false,
        }
    }

    async fn download(
        address: std::net::SocketAddr,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let mut out = Vec::new();
        test_xvd()
            .download_file_http(
                &client,
                &[format!("http://{address}/file")],
                &mut out,
                &test_segment(),
                [0u8; 32],
                |_, _| {},
                0,
                |_| Ok(()),
            )
            .await?;
        Ok(out)
    }

    #[tokio::test]
    async fn download_reconnects_after_a_dropped_connection() {
        let body: Vec<u8> = (0..PAGE_SIZE).map(|index| (index % 251) as u8).collect();
        let (address, server) = spawn_server(ServerMode::DropFirstThenServe(body.clone())).await;

        let out = tokio::time::timeout(std::time::Duration::from_secs(10), download(address))
            .await
            .expect("a reconnect must complete")
            .expect("the segment should download after one reconnect");

        assert_eq!(out, body);
        server.abort();
    }

    #[tokio::test]
    async fn download_exhausts_the_reconnect_budget() {
        let (address, server) = spawn_server(ServerMode::NotFound).await;

        let error = tokio::time::timeout(std::time::Duration::from_secs(10), download(address))
            .await
            .expect("a failing download must not hang")
            .expect_err("five failed reconnects must return an error")
            .to_string();

        assert!(error.contains("5 reconnect attempts"), "{error}");
        assert!(error.contains("offset 0"), "{error}");
        server.abort();
    }

    #[derive(Clone)]
    enum RangeMode {
        Always500,
        ServeRange,
        ServePrefixThenFail(usize),
    }

    async fn spawn_range_server(
        body: Vec<u8>,
        mode: RangeMode,
    ) -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let handle = tokio::spawn(async move {
            let mut connection = 0usize;
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while let Ok(1) = socket.read(&mut byte).await {
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let range = text
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("range")
                            .then(|| value.trim().to_owned())
                    })
                    .unwrap_or_default();
                recorded.lock().unwrap().push(range.clone());
                let start = range
                    .strip_prefix("bytes=")
                    .and_then(|value| value.split_once('-'))
                    .and_then(|(start, _)| start.parse::<usize>().ok())
                    .unwrap_or(0);
                let is_first = connection == 0;
                connection += 1;
                let serve = match &mode {
                    RangeMode::Always500 => false,
                    RangeMode::ServeRange => true,
                    RangeMode::ServePrefixThenFail(_) => is_first,
                };
                if !serve {
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = socket.shutdown().await;
                    continue;
                }
                let slice = &body[start.min(body.len())..];
                let write_len = match &mode {
                    RangeMode::ServePrefixThenFail(prefix) => (*prefix).min(slice.len()),
                    _ => slice.len(),
                };
                let headers = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{}/{}\r\nConnection: close\r\n\r\n",
                    slice.len(),
                    body.len().saturating_sub(1),
                    body.len()
                );
                let _ = socket.write_all(headers.as_bytes()).await;
                let _ = socket.write_all(&slice[..write_len]).await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://{address}/file"), requests, handle)
    }

    async fn download_urls(
        urls: &[String],
        segment: &SegmentFile,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let mut out = Vec::new();
        test_xvd()
            .download_file_http(
                &client,
                urls,
                &mut out,
                segment,
                [0u8; 32],
                |_, _| {},
                0,
                |_| Ok(()),
            )
            .await?;
        Ok(out)
    }

    fn segment_of_length(length: u64) -> SegmentFile {
        SegmentFile {
            offset: 0,
            length,
            data_hashs: vec![],
            keep_encrypted: false,
        }
    }

    #[tokio::test]
    async fn download_falls_back_to_the_next_host() {
        let body: Vec<u8> = (0..PAGE_SIZE).map(|index| (index % 251) as u8).collect();
        let (first, _, first_server) = spawn_range_server(body.clone(), RangeMode::Always500).await;
        let (second, requests, second_server) =
            spawn_range_server(body.clone(), RangeMode::ServeRange).await;

        let out = download_urls(&[first, second], &segment_of_length(PAGE_SIZE as u64))
            .await
            .expect("the second host must serve the segment");

        assert_eq!(out, body);
        assert_eq!(requests.lock().unwrap().len(), 1);
        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn download_resumes_on_the_next_host_at_the_same_offset() {
        let body: Vec<u8> = (0..PAGE_SIZE * 4)
            .map(|index| (index % 251) as u8)
            .collect();
        let (first, _, first_server) =
            spawn_range_server(body.clone(), RangeMode::ServePrefixThenFail(PAGE_SIZE)).await;
        let (second, requests, second_server) =
            spawn_range_server(body.clone(), RangeMode::ServeRange).await;

        let out = download_urls(&[first, second], &segment_of_length(body.len() as u64))
            .await
            .expect("the next host must resume the segment");

        assert_eq!(out, body);
        let ranges = requests.lock().unwrap().clone();
        assert!(
            ranges
                .first()
                .is_some_and(|range| range.starts_with(&format!("bytes={PAGE_SIZE}-"))),
            "expected the second host to resume at {PAGE_SIZE}, got {ranges:?}"
        );
        first_server.abort();
        second_server.abort();
    }
}
