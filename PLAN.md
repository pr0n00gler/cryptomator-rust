# S3FS Implementation Plan

## Goals
- Add a new provider `S3FS` that implements `FileSystem` and a corresponding `File` implementation for S3 objects.
- Support S3-compatible endpoints (AWS S3, MinIO, LocalStack).
- Preserve CryptoFS expectations (sync Read/Write/Seek, metadata, directory semantics).
- Provide comprehensive automated tests for correctness and edge cases.

## Key Constraints & Observations
- `FileSystem` and `File` traits are **sync** (Read/Write/Seek + metadata). S3 clients are typically **async**, but `rust-s3` offers both blocking and async.
- S3 is an object store (no real directories). Must emulate directories for `create_dir`, `read_dir`, `remove_dir`.
- CryptoFS performs random access and partial writes. `S3FS::File` must support Seek + Read/Write correctly.
- `FileSystem::stats` is used by WebDAV for quota; S3 has no native quota -> return defaults or configured values.

## Design Decisions (with rationale)
- **Client**: use `rust-s3 = "0.37.1"` crate for S3-compatible API with blocking and async helpers.
- **Sync wrapper**: prefer `rust-s3` blocking API to avoid internal Tokio runtime complexity.
- **Directory emulation**:
  - Treat "directories" as key prefixes.
  - On `create_dir`, create a zero-length "marker" object with trailing `/` to allow empty dirs.
  - `read_dir` uses `list` with `prefix` + `delimiter: "/"` to get files + common prefixes.
- **File I/O strategy**:
  - **Read-only**: use ranged GET requests (rust-s3 supports range headers).
  - **Read/Write**: use a local temp file staging approach (download once if needed, write locally, upload on flush/drop).
  - **Large uploads**: use multipart upload above a size threshold (rust-s3 supports multipart).
  - **Truncate/append**: implemented on staging file, followed by re-upload on flush.
- **Error handling**: define `S3FsError` (thiserror) and convert to `Box<dyn Error>` per trait.

## Implementation Steps

### 1) New Provider Module
- Create `src/providers/s3_fs.rs`.
- Export in `src/providers/mod.rs` as `pub use self::s3_fs::S3Fs;`.

### 2) Configuration & Initialization
- Define `S3FsConfig`:
  - `bucket`, `prefix`, `region`, `endpoint`, `force_path_style`, `access_key`, `secret_key`, `session_token`, timeouts.
- `S3Fs::new(config)`:
  - Build `s3::Bucket` using credentials + region + endpoint.
  - Apply path-style if needed for LocalStack.
  - Validate bucket existence (head bucket) and `prefix` root (optional).

### 3) Path Mapping
- Normalize `Path` inputs:
  - Strip leading `/`.
  - Convert to UTF-8 (CryptoFS already requires UTF-8).
  - Join with `prefix` using `/`.
- Keep a helper `path_to_key(path)` and `dir_to_prefix(path)`.

### 4) Directory Semantics
- `create_dir`: create marker object `prefix/dir/` (zero-length).
- `create_dir_all`: same as `create_dir` (S3 prefixes are implicit).
- `read_dir`:
  - `list` with `prefix: dir_prefix` and `delimiter: "/"`.
  - Convert `common_prefixes` to `DirEntry` with `is_dir = true`.
  - Convert objects to `DirEntry` with `is_file = true`, skipping the directory marker itself.
- `remove_dir`: delete all objects with that prefix (paginated list + batch delete).
- `exists`: for files `head_object`; for dirs `list` with `max_keys=1`.

### 5) File Handle: `S3File`
- Implement `File` trait + `Read/Write/Seek`:
  - Fields: key, bucket, local temp file path, cursor, dirty flag, size, etag, metadata.
  - Read-only mode: use ranged GET to fill buffers as needed.
  - Read/write mode: stage on disk (using `tempfile`), upload on `flush()` and `Drop`.
  - Ensure `metadata()` uses local file size if staged; otherwise use `head_object`.
- `open_file`:
  - Honor `OpenOptions`:
    - `create_new`: use `head_object` to check existence and fail if present.
    - `truncate`: create empty object or empty temp file and mark dirty.
    - `append`: fetch length and seek to end in temp file.
- `create_file`: create_new + empty object write.

### 6) Copy/Move
- `copy_file`: use `copy_object`.
- `move_file`: `copy_file` then `remove_file`.
- `move_dir`: list under source prefix, copy each object to destination prefix, then delete source.

### 7) Metadata & Stats
- `metadata`: use `head_object` (len, last_modified). For dirs, return `is_dir=true`, len=0.
- `stats`: return `Stats::default()` or allow configured total/available if provided in config.

### 8) Testing Strategy

#### Unit Tests (fast)
- Path/key normalization.
- Directory marker behavior.
- OpenOptions handling (create_new, truncate, append).
- Range read logic (seek/read without full download).

#### Integration Tests (LocalStack)
Use LocalStack via `testcontainers`:
- Setup LocalStack S3 container.
- Create bucket + prefix.
- `create_dir`, `read_dir` with empty and non-empty dirs.
- `open_file` read/write/seek; verify content round-trips.
- `create_new` fails if object exists.
- `copy_file`, `move_file`, `remove_file`, `remove_dir`.
- Large file upload to exercise multipart.
- Concurrent access sanity (optional).

#### Test gating
- If `S3_TEST_*` env vars set, use provided endpoint/bucket.
- Otherwise, spin LocalStack via `testcontainers` or skip with a clear message.

### 9) Documentation/Notes
- Add provider usage examples to README if needed.
- Clarify that `stats` uses defaults unless configured.
- Note performance implications of staging file strategy.

## Risks & Pitfalls (and mitigations)
- **Seek/Write to remote object**: staging file to ensure correctness.
- **Empty directories**: explicit marker objects.
- **Large writes**: multipart uploads to avoid memory spikes.
- **Consistency**: S3’s eventual consistency on overwrite; refresh metadata after upload.
- **Credentials**: avoid storing secrets in logs; keep config minimal.

## Validation Checklist
- `make test` runs unit tests.
- Integration tests pass against LocalStack.
- WebDAV/NFS still pass (provider is additive).
- `make clippy` and `cargo fmt` clean.
