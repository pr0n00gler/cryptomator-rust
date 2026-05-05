use crate::cryptofs::{DirEntry, File, FileSystem, Metadata, OpenOptions, Stats};
use reqwest::blocking::Client;
use reqwest::header::{CONTENT_TYPE, ETAG, HeaderMap, HeaderValue, IF_MATCH};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const PENDING_WRITE_FLUSH_THRESHOLD: usize = 8 * 1024 * 1024;

/// A [`FileSystem`] implementation backed by a WebDAV server.
///
/// Reads use HTTP Range GET requests to fetch only the requested byte
/// ranges, avoiding the need to buffer entire files in memory. Writes are
/// accumulated in memory and flushed back to the server via a
/// read-modify-write cycle on [`flush`].
#[derive(Clone)]
pub struct WebDavFs {
    base_url: String,
    client: Client,
}

impl WebDavFs {
    pub fn new(
        base_url: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self, Box<dyn Error>> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let mut builder = Client::builder();
        builder = builder
            .danger_accept_invalid_certs(false)
            .connect_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(300));
        if let Some(user) = username {
            let pass = password.unwrap_or("");
            builder = builder.default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                let credentials = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    format!("{user}:{pass}"),
                );
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    HeaderValue::from_str(&format!("Basic {credentials}"))?,
                );
                headers
            });
        }
        let client = builder.build()?;
        Ok(WebDavFs { base_url, client })
    }

    fn url_for<P: AsRef<Path>>(&self, path: P) -> String {
        let segments: Vec<String> = path
            .as_ref()
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => {
                    Some(urlencoding::encode(&s.to_string_lossy()).into_owned())
                }
                _ => None,
            })
            .collect();
        if segments.is_empty() {
            format!("{}/", self.base_url)
        } else {
            format!("{}/{}", self.base_url, segments.join("/"))
        }
    }

    fn propfind(&self, url: &str, depth: &str) -> Result<String, Box<dyn Error>> {
        let body = r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:resourcetype/>
    <d:getcontentlength/>
    <d:getlastmodified/>
    <d:creationdate/>
  </d:prop>
</d:propfind>"#;

        let resp = self
            .client
            .request(reqwest::Method::from_bytes(b"PROPFIND")?, url)
            .header("Depth", depth)
            .header(CONTENT_TYPE, "application/xml")
            .body(body)
            .send()?;

        let status = resp.status().as_u16();
        if status != 207 && status != 200 {
            return Err(format!("PROPFIND failed with status {status}").into());
        }
        Ok(resp.text()?)
    }

    fn put_empty_checked(&self, url: &str) -> Result<Option<String>, Box<dyn Error>> {
        let resp = self.client.put(url).body(Vec::new()).send()?;
        if resp.status().is_success() {
            return Ok(etag_from_headers(resp.headers()));
        }

        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        Err(format!("PUT {url} failed with status {status}: {body}").into())
    }

    fn parse_multistatus(xml: &str) -> Vec<PropfindEntry> {
        parse_multistatus_xml(xml)
    }
}

fn etag_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn head_etag(client: &Client, url: &str) -> Option<String> {
    client
        .head(url)
        .send()
        .ok()
        .filter(|resp| resp.status().is_success())
        .and_then(|resp| etag_from_headers(resp.headers()))
}

fn webdav_conflict_error(url: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        format!("WebDAV write conflict for {url}"),
    )
}

struct TempUploadFile {
    path: PathBuf,
    file: fs::File,
}

impl TempUploadFile {
    fn new() -> std::io::Result<Self> {
        for _ in 0..16 {
            let path = std::env::temp_dir()
                .join(format!("cryptomator-webdav-{}.tmp", uuid::Uuid::new_v4()));
            match fs::OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&path)
            {
                Ok(file) => return Ok(Self { path, file }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "failed to allocate a unique WebDAV temporary file",
        ))
    }

    fn set_len(&mut self, len: u64) -> std::io::Result<()> {
        self.file.set_len(len)
    }
}

impl Read for TempUploadFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for TempUploadFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Seek for TempUploadFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

impl Drop for TempUploadFile {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %err,
                    "failed to remove WebDAV temporary file"
                );
            }
        }
    }
}

struct PropfindEntry {
    href: String,
    is_collection: bool,
    content_length: u64,
    last_modified: SystemTime,
    creation_date: SystemTime,
}

fn parse_http_date(s: &str) -> SystemTime {
    httpdate::parse_http_date(s).unwrap_or(SystemTime::UNIX_EPOCH)
}

fn days_since_epoch(year: i64, month: u64, day: u64) -> i64 {
    // Simplified days-since-epoch calculation
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u64;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

fn parse_iso8601_date(s: &str) -> SystemTime {
    // Try HTTP date first (some servers use it for creationdate)
    if let Ok(t) = httpdate::parse_http_date(s) {
        return t;
    }
    // Try simple ISO 8601 / RFC 3339 parsing: "YYYY-MM-DDThh:mm:ssZ"
    use std::time::Duration;
    let s = s.trim();
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() == 2 {
        let date_parts: Vec<&str> = parts[0].split('-').collect();
        let time_str = parts[1].trim_end_matches('Z').trim_end_matches("+00:00");
        let time_parts: Vec<&str> = time_str.split(':').collect();
        if date_parts.len() == 3 && time_parts.len() >= 2 {
            if let (Ok(year), Ok(month), Ok(day)) = (
                date_parts[0].parse::<i64>(),
                date_parts[1].parse::<u64>(),
                date_parts[2].parse::<u64>(),
            ) {
                let hour = time_parts[0].parse::<u64>().unwrap_or(0);
                let min = time_parts[1].parse::<u64>().unwrap_or(0);
                let sec = if time_parts.len() > 2 {
                    time_parts[2]
                        .split('.')
                        .next()
                        .unwrap_or("0")
                        .parse::<u64>()
                        .unwrap_or(0)
                } else {
                    0
                };
                let days_from_epoch = days_since_epoch(year, month, day);
                if let Some(total_secs) = days_from_epoch
                    .checked_mul(86400)
                    .and_then(|d| d.checked_add((hour * 3600 + min * 60 + sec) as i64))
                {
                    if total_secs >= 0 {
                        return SystemTime::UNIX_EPOCH + Duration::from_secs(total_secs as u64);
                    }
                }
            }
        }
    }
    SystemTime::UNIX_EPOCH
}

fn parse_multistatus_xml(xml: &str) -> Vec<PropfindEntry> {
    let doc = match roxmltree::Document::parse(xml) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let mut entries = Vec::new();

    for node in doc.descendants() {
        if node.tag_name().name() == "response" {
            let mut href = String::new();
            let mut is_collection = false;
            let mut content_length: u64 = 0;
            let mut last_modified = SystemTime::UNIX_EPOCH;
            let mut creation_date = SystemTime::UNIX_EPOCH;

            for child in node.descendants() {
                match child.tag_name().name() {
                    "href" => {
                        if let Some(text) = child.text() {
                            href = text.to_string();
                        }
                    }
                    "collection" => {
                        is_collection = true;
                    }
                    "getcontentlength" => {
                        if let Some(text) = child.text() {
                            content_length = text.parse().unwrap_or(0);
                        }
                    }
                    "getlastmodified" => {
                        if let Some(text) = child.text() {
                            last_modified = parse_http_date(text);
                        }
                    }
                    "creationdate" => {
                        if let Some(text) = child.text() {
                            creation_date = parse_iso8601_date(text);
                        }
                    }
                    _ => {}
                }
            }

            entries.push(PropfindEntry {
                href,
                is_collection,
                content_length,
                last_modified,
                creation_date,
            });
        }
    }

    entries
}

fn metadata_from_propfind(entry: &PropfindEntry) -> Metadata {
    Metadata {
        is_dir: entry.is_collection,
        is_file: !entry.is_collection,
        len: entry.content_length,
        modified: entry.last_modified,
        accessed: entry.last_modified,
        created: entry.creation_date,

        #[cfg(unix)]
        uid: 0,
        #[cfg(unix)]
        gid: 0,
    }
}

fn extract_url_path(url: &str) -> &str {
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    without_scheme
        .find('/')
        .map_or("", |i| &without_scheme[i..])
}

fn href_to_path(href: &str, base_url: &str) -> PathBuf {
    let url_path = extract_url_path(href);
    let base_path = extract_url_path(base_url);

    let relative = url_path
        .strip_prefix(base_path)
        .unwrap_or(url_path)
        .trim_start_matches('/')
        .trim_end_matches('/');

    let decoded = urlencoding::decode(relative).unwrap_or(std::borrow::Cow::Borrowed(relative));

    if decoded.is_empty() {
        PathBuf::from("/")
    } else {
        PathBuf::from(format!("/{decoded}"))
    }
}

pub(crate) struct WebDavFile {
    url: String,
    client: Client,
    current_pos: u64,
    content_length: u64,
    pending_writes: BTreeMap<u64, Vec<u8>>,
    meta: Metadata,
    etag: Option<String>,
}

impl WebDavFile {
    /// Returns the effective file length considering both the server-side
    /// content length and any pending writes that extend past it.
    fn effective_length(&self) -> u64 {
        let mut len = self.content_length;
        for (&offset, data) in &self.pending_writes {
            let end = offset + data.len() as u64;
            if end > len {
                len = end;
            }
        }
        len
    }

    /// Returns `true` if there are any unflushed writes.
    fn is_dirty(&self) -> bool {
        !self.pending_writes.is_empty()
    }

    fn pending_write_bytes(&self) -> usize {
        self.pending_writes.values().map(Vec::len).sum()
    }

    fn new_spooled_file() -> std::io::Result<TempUploadFile> {
        TempUploadFile::new()
    }

    fn download_existing_to_spool(&self) -> std::io::Result<TempUploadFile> {
        let mut spool = Self::new_spooled_file()?;
        if self.content_length == 0 {
            return Ok(spool);
        }

        let mut resp = self
            .client
            .get(&self.url)
            .send()
            .map_err(std::io::Error::other)?;
        if !resp.status().is_success() {
            return Err(std::io::Error::other(format!(
                "GET for flush failed with status {}",
                resp.status()
            )));
        }

        std::io::copy(&mut resp, &mut spool)?;
        spool.rewind()?;
        Ok(spool)
    }

    fn download_prefix_to_spool(&self, len: u64) -> std::io::Result<TempUploadFile> {
        let mut spool = Self::new_spooled_file()?;
        if len == 0 {
            return Ok(spool);
        }

        let resp = self
            .client
            .get(&self.url)
            .header("Range", format!("bytes=0-{}", len - 1))
            .send()
            .map_err(std::io::Error::other)?;
        let status = resp.status().as_u16();
        if status != 206 && status != 200 {
            return Err(std::io::Error::other(format!(
                "GET for truncate failed with status {}",
                resp.status()
            )));
        }

        let copied = std::io::copy(&mut resp.take(len), &mut spool)?;
        if copied < len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("WebDAV server returned {copied} bytes while truncating to {len}"),
            ));
        }

        spool.rewind()?;
        Ok(spool)
    }

    fn upload_spool(&mut self, mut spool: TempUploadFile, new_len: u64) -> std::io::Result<()> {
        spool.rewind()?;
        let body = reqwest::blocking::Body::sized(spool, new_len);
        let mut request = self.client.put(&self.url).body(body);
        if let Some(etag) = &self.etag {
            request = request.header(IF_MATCH, etag);
        } else {
            tracing::warn!(
                url = %self.url,
                "WebDAV server did not provide an ETag; flush is best-effort"
            );
        }

        let resp = request.send().map_err(std::io::Error::other)?;
        if resp.status().as_u16() == 412 {
            return Err(webdav_conflict_error(&self.url));
        }
        if !resp.status().is_success() {
            return Err(std::io::Error::other(format!(
                "PUT failed with status {}",
                resp.status()
            )));
        }

        self.etag =
            etag_from_headers(resp.headers()).or_else(|| head_etag(&self.client, &self.url));
        if self.etag.is_none() {
            tracing::warn!(
                url = %self.url,
                "WebDAV server did not provide a post-PUT ETag; subsequent flushes are best-effort"
            );
        }
        self.content_length = new_len;
        self.meta.len = new_len;
        Ok(())
    }
}

impl fmt::Debug for WebDavFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebDavFile")
            .field("url", &self.url)
            .field("pos", &self.current_pos)
            .field("content_length", &self.content_length)
            .field("pending_writes", &self.pending_writes.len())
            .finish()
    }
}

impl Read for WebDavFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let effective_len = self.effective_length();
        if buf.is_empty() || self.current_pos >= effective_len {
            return Ok(0);
        }

        let start = self.current_pos;
        let end = (start + buf.len() as u64 - 1).min(effective_len - 1);
        let read_len = (end - start + 1) as usize;

        // Fetch from server if the range overlaps with server-side content.
        if start < self.content_length {
            let server_end = end.min(self.content_length - 1);
            let resp = self
                .client
                .get(&self.url)
                .header("Range", format!("bytes={start}-{server_end}"))
                .send()
                .map_err(std::io::Error::other)?;

            let status = resp.status().as_u16();
            if status == 206 {
                let bytes = resp.bytes().map_err(std::io::Error::other)?;
                let n = bytes.len().min(read_len);
                buf[..n].copy_from_slice(&bytes[..n]);
                if read_len > n {
                    buf[n..read_len].fill(0);
                }
            } else if status == 200 {
                let bytes = resp.bytes().map_err(std::io::Error::other)?;
                let source_start = usize::try_from(start).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "read offset exceeds platform address space",
                    )
                })?;
                if source_start > bytes.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "server ignored Range and returned a body shorter than the requested offset",
                    ));
                }
                let n = (bytes.len() - source_start).min(read_len);
                buf[..n].copy_from_slice(&bytes[source_start..source_start + n]);
                if read_len > n {
                    buf[n..read_len].fill(0);
                }
            } else {
                return Err(std::io::Error::other(format!(
                    "GET range failed with status {}",
                    resp.status()
                )));
            }
        } else {
            // Entirely beyond server content; fill with zeros first.
            buf[..read_len].fill(0);
        }

        // Overlay any pending writes that intersect the requested range.
        for (&write_offset, write_data) in &self.pending_writes {
            let write_end = write_offset + write_data.len() as u64;
            if write_end <= start || write_offset > end {
                continue;
            }
            let overlap_start = start.max(write_offset);
            let overlap_end = (end + 1).min(write_end);
            let buf_offset = (overlap_start - start) as usize;
            let data_offset = (overlap_start - write_offset) as usize;
            let len = (overlap_end - overlap_start) as usize;
            buf[buf_offset..buf_offset + len]
                .copy_from_slice(&write_data[data_offset..data_offset + len]);
        }

        self.current_pos += read_len as u64;
        Ok(read_len)
    }
}

impl Write for WebDavFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let new_start = self.current_pos;
        let new_end = new_start + buf.len() as u64;

        // Collect only the keys of overlapping entries, then remove and
        // process one at a time to avoid cloning data buffers.
        let overlapping_keys: Vec<u64> = self
            .pending_writes
            .range(..new_end)
            .filter(|&(&offset, data)| offset + data.len() as u64 > new_start)
            .map(|(&offset, _)| offset)
            .collect();

        for e_offset in overlapping_keys {
            let e_data = self.pending_writes.remove(&e_offset).unwrap();
            let e_end = e_offset + e_data.len() as u64;

            if e_offset >= new_start && e_end <= new_end {
                // Existing entry entirely within new write: remove it (already done).
            } else if e_offset < new_start && e_end <= new_end {
                // Existing entry starts before new write and ends within it:
                // truncate to [e_offset, new_start).
                let trimmed = e_data[..(new_start - e_offset) as usize].to_vec();
                self.pending_writes.insert(e_offset, trimmed);
            } else if e_offset >= new_start && e_end > new_end {
                // Existing entry starts within new write and extends past it:
                // keep the tail at [new_end, e_end).
                let tail = e_data[(new_end - e_offset) as usize..].to_vec();
                self.pending_writes.insert(new_end, tail);
            } else {
                // Existing entry spans entirely across new write: split into
                // prefix [e_offset, new_start) and suffix [new_end, e_end).
                let prefix = e_data[..(new_start - e_offset) as usize].to_vec();
                let suffix = e_data[(new_end - e_offset) as usize..].to_vec();
                self.pending_writes.insert(e_offset, prefix);
                self.pending_writes.insert(new_end, suffix);
            }
        }

        self.pending_writes.insert(new_start, buf.to_vec());
        self.current_pos += buf.len() as u64;
        if self.pending_write_bytes() > PENDING_WRITE_FLUSH_THRESHOLD {
            self.flush()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.pending_writes.is_empty() {
            return Ok(());
        }

        let new_len = self.effective_length();
        let mut spool = self.download_existing_to_spool()?;
        spool.set_len(new_len)?;

        // Apply all pending writes.
        for (&offset, write_data) in &self.pending_writes {
            spool.seek(SeekFrom::Start(offset))?;
            spool.write_all(write_data)?;
        }

        self.upload_spool(spool, new_len)?;
        self.pending_writes.clear();
        Ok(())
    }
}

impl Seek for WebDavFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let effective_len = self.effective_length();
        match pos {
            SeekFrom::Start(p) => self.current_pos = p,
            SeekFrom::Current(p) => {
                let new = self.current_pos as i64 + p;
                if new < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "seek before start of file",
                    ));
                }
                self.current_pos = new as u64;
            }
            SeekFrom::End(p) => {
                let new = effective_len as i64 + p;
                if new < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "seek before start of file",
                    ));
                }
                self.current_pos = new as u64;
            }
        }
        Ok(self.current_pos)
    }
}

impl File for WebDavFile {
    fn metadata(&self) -> Result<Metadata, Box<dyn Error>> {
        let mut meta = self.meta;
        meta.len = self.effective_length();
        Ok(meta)
    }

    fn fsync(&mut self) -> std::io::Result<()> {
        self.flush()
    }

    fn set_len(&mut self, len: u64) -> std::io::Result<()> {
        self.flush()?;
        if len == self.content_length {
            return Ok(());
        }

        let mut spool = if len < self.content_length {
            self.download_prefix_to_spool(len)?
        } else {
            self.download_existing_to_spool()?
        };
        spool.set_len(len)?;
        self.upload_spool(spool, len)
    }
}

impl Drop for WebDavFile {
    fn drop(&mut self) {
        if self.is_dirty() {
            tracing::warn!(url = %self.url, "WebDavFile dropped with unflushed writes, attempting flush");
            if let Err(e) = self.flush() {
                tracing::error!(url = %self.url, error = %e, "failed to flush writes on drop");
            }
        }
    }
}

impl FileSystem for WebDavFs {
    fn read_dir<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn Iterator<Item = DirEntry>>, Box<dyn Error>> {
        let mut url = self.url_for(&path);
        if !url.ends_with('/') {
            url.push('/');
        }
        let xml = self.propfind(&url, "1")?;
        let all_entries = Self::parse_multistatus(&xml);

        let request_path = path.as_ref().to_string_lossy().to_string();
        let base_url = self.base_url.clone();

        let entries: Vec<DirEntry> = all_entries
            .iter()
            .filter_map(|e| {
                let entry_path = href_to_path(&e.href, &base_url);
                let entry_str = entry_path.to_string_lossy().to_string();
                let request_normalized = request_path.trim_end_matches('/');
                let entry_normalized = entry_str.trim_end_matches('/');

                // Skip the directory itself (only include children)
                if entry_normalized == request_normalized
                    || (request_normalized.is_empty() && entry_normalized == "/")
                {
                    return None;
                }

                let file_name = entry_path.file_name().unwrap_or_default().to_os_string();

                Some(DirEntry {
                    path: entry_path,
                    metadata: metadata_from_propfind(e),
                    file_name,
                })
            })
            .collect();

        Ok(Box::new(entries.into_iter()))
    }

    fn create_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        let mut url = self.url_for(&path);
        if !url.ends_with('/') {
            url.push('/');
        }
        let resp = self
            .client
            .request(reqwest::Method::from_bytes(b"MKCOL")?, &url)
            .send()?;

        let status = resp.status().as_u16();
        if status != 201 && status != 200 {
            let body = resp.text().unwrap_or_default();
            return Err(format!("MKCOL {url} failed with status {status}: {body}").into());
        }
        Ok(())
    }

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        let path = path.as_ref();
        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component);
            match self.create_dir(&current) {
                Ok(()) => {}
                Err(_) if self.exists(&current) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn open_file<P: AsRef<Path>>(
        &self,
        path: P,
        options: OpenOptions,
    ) -> Result<Box<dyn File>, Box<dyn Error>> {
        let url = self.url_for(&path);

        let now = SystemTime::now();
        let empty_meta = Metadata {
            is_dir: false,
            is_file: true,
            len: 0,
            modified: now,
            accessed: now,
            created: now,
            #[cfg(unix)]
            uid: 0,
            #[cfg(unix)]
            gid: 0,
        };

        if options.create_new {
            if self.exists(&path) {
                return Err("file already exists".into());
            }
            let etag = self
                .put_empty_checked(&url)?
                .or_else(|| head_etag(&self.client, &url));
            return Ok(Box::new(WebDavFile {
                url,
                client: self.client.clone(),
                current_pos: 0,
                content_length: 0,
                pending_writes: BTreeMap::new(),
                meta: empty_meta,
                etag,
            }));
        }

        // Use HEAD to check existence and get content length without
        // downloading the file body.
        let resp = self.client.head(&url).send()?;
        let file_exists = resp.status().is_success();
        let mut etag = etag_from_headers(resp.headers());

        if !file_exists && !options.create {
            return Err("file not found".into());
        }

        let (content_length, meta) = if file_exists && !options.truncate {
            let content_length = resp
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let last_modified = resp
                .headers()
                .get("last-modified")
                .and_then(|v| v.to_str().ok())
                .map(parse_http_date)
                .unwrap_or(SystemTime::UNIX_EPOCH);
            let meta = Metadata {
                is_dir: false,
                is_file: true,
                len: content_length,
                modified: last_modified,
                accessed: last_modified,
                created: SystemTime::UNIX_EPOCH,
                #[cfg(unix)]
                uid: 0,
                #[cfg(unix)]
                gid: 0,
            };
            (content_length, meta)
        } else {
            if !file_exists {
                etag = self.put_empty_checked(&url)?;
            }
            (0, empty_meta)
        };

        let initial_pos = if options.append { content_length } else { 0 };

        // When truncating an existing file, upload an empty body immediately
        // so the server-side content is cleared.
        let content_length = if options.truncate && file_exists {
            etag = self.put_empty_checked(&url)?;
            0
        } else {
            content_length
        };
        if (options.truncate || !file_exists) && etag.is_none() {
            etag = head_etag(&self.client, &url);
        }

        Ok(Box::new(WebDavFile {
            url,
            client: self.client.clone(),
            current_pos: initial_pos,
            content_length,
            pending_writes: BTreeMap::new(),
            meta,
            etag,
        }))
    }

    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn File>, Box<dyn Error>> {
        let url = self.url_for(&path);
        let etag = self
            .put_empty_checked(&url)?
            .or_else(|| head_etag(&self.client, &url));

        let now = SystemTime::now();
        let meta = Metadata {
            is_dir: false,
            is_file: true,
            len: 0,
            modified: now,
            accessed: now,
            created: now,
            #[cfg(unix)]
            uid: 0,
            #[cfg(unix)]
            gid: 0,
        };

        Ok(Box::new(WebDavFile {
            url,
            client: self.client.clone(),
            current_pos: 0,
            content_length: 0,
            pending_writes: BTreeMap::new(),
            meta,
            etag,
        }))
    }

    fn exists<P: AsRef<Path>>(&self, path: P) -> bool {
        let url = self.url_for(&path);
        match self.client.head(&url).send() {
            Ok(resp) if resp.status().is_success() => true,
            Ok(resp) if resp.status().as_u16() == 404 => false,
            Ok(resp) if resp.status().as_u16() == 405 => {
                // HEAD may not be supported for directories on some WebDAV
                // servers; fall back to a depth-0 PROPFIND to check existence.
                // Try without trailing slash first, then with.
                self.propfind(&url, "0").is_ok()
                    || (!url.ends_with('/') && self.propfind(&format!("{url}/"), "0").is_ok())
            }
            _ => {
                // The server may have returned a redirect (e.g. 301 for a
                // directory without trailing slash) that reqwest could not
                // follow for HEAD.  Retry with a trailing slash.
                if !url.ends_with('/') {
                    let dir_url = format!("{url}/");
                    match self.client.head(&dir_url).send() {
                        Ok(resp) if resp.status().is_success() => true,
                        Ok(resp) if resp.status().as_u16() == 405 => {
                            self.propfind(&dir_url, "0").is_ok()
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            }
        }
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        let url = self.url_for(&path);
        let resp = self.client.delete(&url).send()?;
        let status = resp.status().as_u16();
        if status != 204 && status != 200 {
            let body = resp.text().unwrap_or_default();
            return Err(format!("DELETE {url} failed with status {status}: {body}").into());
        }
        Ok(())
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        let mut url = self.url_for(&path);
        if !url.ends_with('/') {
            url.push('/');
        }
        let resp = self.client.delete(&url).send()?;
        let status = resp.status().as_u16();
        if status != 204 && status != 200 {
            let body = resp.text().unwrap_or_default();
            return Err(format!("DELETE {url} failed with status {status}: {body}").into());
        }
        Ok(())
    }

    fn copy_file<P: AsRef<Path>>(&self, src: P, dest: P) -> Result<(), Box<dyn Error>> {
        let src_url = self.url_for(&src);
        let dest_url = self.url_for(&dest);
        let resp = self
            .client
            .request(reqwest::Method::from_bytes(b"COPY")?, &src_url)
            .header("Destination", &dest_url)
            .header("Overwrite", "T")
            .send()?;

        let status = resp.status().as_u16();
        if status != 201 && status != 204 && status != 200 {
            let body = resp.text().unwrap_or_default();
            return Err(format!(
                "COPY {src_url} -> {dest_url} failed with status {status}: {body}"
            )
            .into());
        }
        Ok(())
    }

    fn move_file<P: AsRef<Path>>(&self, src: P, dest: P) -> Result<(), Box<dyn Error>> {
        let src_url = self.url_for(&src);
        let dest_url = self.url_for(&dest);
        let resp = self
            .client
            .request(reqwest::Method::from_bytes(b"MOVE")?, &src_url)
            .header("Destination", &dest_url)
            .header("Overwrite", "T")
            .send()?;

        let status = resp.status().as_u16();
        if status != 201 && status != 204 && status != 200 {
            let body = resp.text().unwrap_or_default();
            return Err(format!(
                "MOVE {src_url} -> {dest_url} failed with status {status}: {body}"
            )
            .into());
        }
        Ok(())
    }

    fn move_dir<P: AsRef<Path>>(&self, src: P, dest: P) -> Result<(), Box<dyn Error>> {
        let src_url = self.url_for(&src);
        let dest_url = self.url_for(&dest);
        let resp = self
            .client
            .request(reqwest::Method::from_bytes(b"MOVE")?, &src_url)
            .header("Destination", &dest_url)
            .header("Overwrite", "T")
            .send()?;

        let status = resp.status().as_u16();
        if status != 201 && status != 204 && status != 200 {
            let body = resp.text().unwrap_or_default();
            return Err(format!(
                "MOVE {src_url} -> {dest_url} failed with status {status}: {body}"
            )
            .into());
        }
        Ok(())
    }

    fn metadata<P: AsRef<Path>>(&self, path: P) -> Result<Metadata, Box<dyn Error>> {
        let url = self.url_for(&path);

        match self.propfind(&url, "0") {
            Ok(xml) => {
                if let Some(entry) = Self::parse_multistatus(&xml).into_iter().next() {
                    return Ok(metadata_from_propfind(&entry));
                }
                // PROPFIND succeeded but returned no entries — try with trailing slash
            }
            Err(e) => {
                // If the URL already has a trailing slash, no point retrying
                if url.ends_with('/') {
                    return Err(e);
                }
                // Otherwise fall through to trailing-slash retry
            }
        }

        // Retry with trailing slash (for directories)
        if !url.ends_with('/') {
            let dir_url = format!("{url}/");
            let xml = self.propfind(&dir_url, "0")?; // propagate errors
            let entry = Self::parse_multistatus(&xml)
                .into_iter()
                .next()
                .ok_or("no metadata returned from PROPFIND")?;
            return Ok(metadata_from_propfind(&entry));
        }

        Err("no metadata returned from PROPFIND".into())
    }

    fn stats<P: AsRef<Path>>(&self, _path: P) -> Result<Stats, Box<dyn Error>> {
        Ok(Stats::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_construction() {
        let fs = WebDavFs::new("http://localhost:8080/dav", None, None)
            .expect("failed to create WebDAV provider");
        assert_eq!(
            fs.url_for("/foo/bar.txt"),
            "http://localhost:8080/dav/foo/bar.txt"
        );
        assert_eq!(
            fs.url_for("foo/bar.txt"),
            "http://localhost:8080/dav/foo/bar.txt"
        );
        assert_eq!(fs.url_for("/"), "http://localhost:8080/dav/");
    }

    #[test]
    fn test_url_construction_trailing_slash() {
        let fs = WebDavFs::new("http://localhost:8080/dav/", None, None)
            .expect("failed to create WebDAV provider");
        assert_eq!(
            fs.url_for("/foo/bar.txt"),
            "http://localhost:8080/dav/foo/bar.txt"
        );
    }

    #[test]
    fn test_url_construction_encodes_segments() {
        let fs = WebDavFs::new("http://localhost:8080/dav", None, None)
            .expect("failed to create WebDAV provider");
        assert_eq!(
            fs.url_for("/foo bar/baz qux.txt"),
            "http://localhost:8080/dav/foo%20bar/baz%20qux.txt"
        );
    }

    #[test]
    fn test_href_to_path() {
        let base = "http://localhost:8080/dav";
        assert_eq!(
            href_to_path("/dav/foo/bar.txt", base),
            PathBuf::from("/foo/bar.txt")
        );
        assert_eq!(href_to_path("/dav/", base), PathBuf::from("/"));
        assert_eq!(
            href_to_path("/dav/some%20file.txt", base),
            PathBuf::from("/some file.txt")
        );
    }

    #[test]
    fn test_parse_multistatus_xml() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/dav/</d:href>
    <d:propstat>
      <d:prop>
        <d:resourcetype><d:collection/></d:resourcetype>
        <d:getlastmodified>Sat, 01 Jan 2022 00:00:00 GMT</d:getlastmodified>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
  <d:response>
    <d:href>/dav/test.txt</d:href>
    <d:propstat>
      <d:prop>
        <d:resourcetype/>
        <d:getcontentlength>42</d:getcontentlength>
        <d:getlastmodified>Sun, 02 Jan 2022 12:00:00 GMT</d:getlastmodified>
        <d:creationdate>Sat, 01 Jan 2022 00:00:00 GMT</d:creationdate>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
  <d:response>
    <d:href>/dav/subdir/</d:href>
    <d:propstat>
      <d:prop>
        <d:resourcetype><d:collection/></d:resourcetype>
        <d:getlastmodified>Fri, 07 Jan 2022 08:00:00 GMT</d:getlastmodified>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#;

        let entries = parse_multistatus_xml(xml);
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].href, "/dav/");
        assert!(entries[0].is_collection);

        assert_eq!(entries[1].href, "/dav/test.txt");
        assert!(!entries[1].is_collection);
        assert_eq!(entries[1].content_length, 42);

        assert_eq!(entries[2].href, "/dav/subdir/");
        assert!(entries[2].is_collection);
    }

    #[test]
    fn test_parse_empty_xml() {
        let entries = parse_multistatus_xml("not valid xml");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_metadata_from_propfind_file() {
        let entry = PropfindEntry {
            href: "/dav/test.txt".to_string(),
            is_collection: false,
            content_length: 1024,
            last_modified: SystemTime::UNIX_EPOCH,
            creation_date: SystemTime::UNIX_EPOCH,
        };
        let meta = metadata_from_propfind(&entry);
        assert!(meta.is_file);
        assert!(!meta.is_dir);
        assert_eq!(meta.len, 1024);
    }

    #[test]
    fn test_metadata_from_propfind_dir() {
        let entry = PropfindEntry {
            href: "/dav/subdir/".to_string(),
            is_collection: true,
            content_length: 0,
            last_modified: SystemTime::UNIX_EPOCH,
            creation_date: SystemTime::UNIX_EPOCH,
        };
        let meta = metadata_from_propfind(&entry);
        assert!(!meta.is_file);
        assert!(meta.is_dir);
    }

    #[test]
    fn test_parse_iso8601_date() {
        use std::time::Duration;
        // 2022-01-01T00:00:00Z is 18993 days after epoch
        let t = parse_iso8601_date("2022-01-01T00:00:00Z");
        assert_ne!(t, SystemTime::UNIX_EPOCH);
        // Verify approximate correctness: 2022-01-01 = 1640995200 unix timestamp
        let expected = SystemTime::UNIX_EPOCH + Duration::from_secs(1_640_995_200);
        assert_eq!(t, expected);
    }

    #[test]
    fn test_extract_url_path() {
        assert_eq!(extract_url_path("http://example.com/dav"), "/dav");
        assert_eq!(extract_url_path("https://example.com/dav/sub"), "/dav/sub");
        assert_eq!(extract_url_path("/dav/foo"), "/dav/foo");
        assert_eq!(extract_url_path("http://example.com"), "");
    }
}
