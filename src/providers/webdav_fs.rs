use crate::cryptofs::{DirEntry, File, FileSystem, Metadata, OpenOptions, Stats};
use reqwest::blocking::Client;
use reqwest::header::{CONTENT_TYPE, HeaderValue};
use std::error::Error;
use std::fmt;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Maximum file size (in bytes) that `WebDavFs` will load into memory.
///
/// **Warning**: `WebDavFs` buffers entire file contents in memory for both
/// reads and writes. Files larger than this limit (256 MiB by default) will
/// be rejected with an error. This provider is not suitable for very large
/// files.
const MAX_WEBDAV_FILE_SIZE: u64 = 256 * 1024 * 1024;

/// A [`FileSystem`] implementation backed by a WebDAV server.
///
/// **Important**: every opened file is buffered entirely in memory.
/// See [`MAX_WEBDAV_FILE_SIZE`] for the enforced size limit. This provider
/// is intended for vault metadata and moderately-sized encrypted chunks,
/// not for multi-gigabyte media files.
#[derive(Clone)]
pub struct WebDavFs {
    base_url: String,
    client: Client,
}

impl WebDavFs {
    pub fn new(base_url: &str, username: Option<&str>, password: Option<&str>) -> Self {
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
                    HeaderValue::from_str(&format!("Basic {credentials}")).unwrap(),
                );
                headers
            });
        }
        let client = builder.build().expect("failed to build HTTP client");
        WebDavFs { base_url, client }
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

    fn parse_multistatus(xml: &str) -> Vec<PropfindEntry> {
        parse_multistatus_xml(xml)
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
    cursor: Cursor<Vec<u8>>,
    dirty: bool,
    meta: Metadata,
}

impl fmt::Debug for WebDavFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebDavFile")
            .field("url", &self.url)
            .field("dirty", &self.dirty)
            .field("len", &self.cursor.get_ref().len())
            .finish()
    }
}

impl Read for WebDavFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.cursor.read(buf)
    }
}

impl Write for WebDavFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.dirty = true;
        self.cursor.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.dirty {
            let data = self.cursor.get_ref().clone();
            let resp = self
                .client
                .put(&self.url)
                .body(data)
                .send()
                .map_err(std::io::Error::other)?;
            if !resp.status().is_success() {
                return Err(std::io::Error::other(format!(
                    "PUT failed with status {}",
                    resp.status()
                )));
            }
            self.dirty = false;
        }
        Ok(())
    }
}

impl Seek for WebDavFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.cursor.seek(pos)
    }
}

impl File for WebDavFile {
    fn metadata(&self) -> Result<Metadata, Box<dyn Error>> {
        let mut meta = self.meta;
        meta.len = self.cursor.get_ref().len() as u64;
        Ok(meta)
    }
}

impl Drop for WebDavFile {
    fn drop(&mut self) {
        if self.dirty {
            tracing::warn!(url = %self.url, "WebDavFile dropped with unflushed data, attempting upload");
            let data = self.cursor.get_ref().clone();
            if let Err(e) = self.client.put(&self.url).body(data).send() {
                tracing::error!(url = %self.url, error = %e, "failed to upload data on drop");
            }
        }
    }
}

impl FileSystem for WebDavFs {
    fn read_dir<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Box<dyn Iterator<Item = DirEntry>>, Box<dyn Error>> {
        let url = self.url_for(&path);
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

        if options.create_new {
            // Need to check existence first for create_new semantics
            if self.exists(&path) {
                return Err("file already exists".into());
            }
            self.client.put(&url).body(Vec::new()).send()?;
            let meta = Metadata {
                is_dir: false,
                is_file: true,
                len: 0,
                modified: SystemTime::now(),
                accessed: SystemTime::now(),
                created: SystemTime::now(),
                #[cfg(unix)]
                uid: 0,
                #[cfg(unix)]
                gid: 0,
            };
            return Ok(Box::new(WebDavFile {
                url,
                client: self.client.clone(),
                cursor: Cursor::new(Vec::new()),
                dirty: false,
                meta,
            }));
        }

        // Try GET first to avoid redundant HEAD + PROPFIND requests
        let resp = self.client.get(&url).send()?;
        let file_exists = resp.status().is_success();

        if !file_exists && !options.create {
            return Err("file not found".into());
        }

        let (data, meta) = if file_exists && !options.truncate {
            let content_length = resp
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            // Size guard
            if content_length > MAX_WEBDAV_FILE_SIZE {
                return Err(format!(
                    "file size {content_length} exceeds maximum {MAX_WEBDAV_FILE_SIZE}"
                )
                .into());
            }
            let last_modified = resp
                .headers()
                .get("last-modified")
                .and_then(|v| v.to_str().ok())
                .map(parse_http_date)
                .unwrap_or(SystemTime::UNIX_EPOCH);
            let bytes = resp.bytes()?.to_vec();
            let meta = Metadata {
                is_dir: false,
                is_file: true,
                len: bytes.len() as u64,
                modified: last_modified,
                accessed: last_modified,
                created: SystemTime::UNIX_EPOCH,
                #[cfg(unix)]
                uid: 0,
                #[cfg(unix)]
                gid: 0,
            };
            (bytes, meta)
        } else {
            if !file_exists {
                self.client.put(&url).body(Vec::new()).send()?;
            }
            let meta = Metadata {
                is_dir: false,
                is_file: true,
                len: 0,
                modified: SystemTime::now(),
                accessed: SystemTime::now(),
                created: SystemTime::now(),
                #[cfg(unix)]
                uid: 0,
                #[cfg(unix)]
                gid: 0,
            };
            (Vec::new(), meta)
        };

        let mut cursor = Cursor::new(data);
        if options.append {
            cursor.seek(SeekFrom::End(0))?;
        }

        Ok(Box::new(WebDavFile {
            url,
            client: self.client.clone(),
            cursor,
            dirty: options.truncate,
            meta,
        }))
    }

    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Box<dyn File>, Box<dyn Error>> {
        let url = self.url_for(&path);
        self.client.put(&url).body(Vec::new()).send()?;

        let meta = Metadata {
            is_dir: false,
            is_file: true,
            len: 0,
            modified: SystemTime::now(),
            accessed: SystemTime::now(),
            created: SystemTime::now(),
            #[cfg(unix)]
            uid: 0,
            #[cfg(unix)]
            gid: 0,
        };

        Ok(Box::new(WebDavFile {
            url,
            client: self.client.clone(),
            cursor: Cursor::new(Vec::new()),
            dirty: false,
            meta,
        }))
    }

    fn exists<P: AsRef<Path>>(&self, path: P) -> bool {
        let url = self.url_for(&path);
        match self.client.head(&url).send() {
            Ok(resp) if resp.status().is_success() => true,
            Ok(resp) if resp.status().as_u16() == 405 => {
                // HEAD may not be supported for directories on some WebDAV
                // servers; fall back to a depth-0 PROPFIND to check existence.
                self.propfind(&url, "0").is_ok()
            }
            _ => false,
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
        let xml = self.propfind(&url, "0")?;
        let entries = Self::parse_multistatus(&xml);
        let entry = entries
            .first()
            .ok_or("no metadata returned from PROPFIND")?;
        Ok(metadata_from_propfind(entry))
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
        let fs = WebDavFs::new("http://localhost:8080/dav", None, None);
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
        let fs = WebDavFs::new("http://localhost:8080/dav/", None, None);
        assert_eq!(
            fs.url_for("/foo/bar.txt"),
            "http://localhost:8080/dav/foo/bar.txt"
        );
    }

    #[test]
    fn test_url_construction_encodes_segments() {
        let fs = WebDavFs::new("http://localhost:8080/dav", None, None);
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
