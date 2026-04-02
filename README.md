![CI](https://github.com/programmer10110/cryptomator-rust/actions/workflows/ci.yml/badge.svg)

# Cryptomator Rust

This is pure-Rust implementation of the [Cryptomator](cryptomator.org) project.

Right now this is a minimal command-line program that unlocks vaults of vault format 8.
After the unlock the vault content can then be accessed via an embedded WebDAV server.

> ### Notice of Non-Affiliation and Disclaimer
> 
> Cryptomator Rust is not affiliated, associated, authorized, endorsed by, or in any way officially connected with Cryptomator™, or any of its subsidiaries or its affiliates.
>
> The official Cryptomator™ website can be found at https://cryptomator.org.
> 
> The name Cryptomator™ as well as related names, marks, emblems and images are registered trademarks of their respective owners.

## Disclaimer

This project is in an early stage and not ready for production use. We recommend to use it only for testing and
evaluation purposes.

## Features

* Full support of the original Cryptomator vaults of vault format 8.
* Works with local vaults
* Unlocked content can be accessed via an embedded WebDav or NFS server;
* Experimental S3-compatible storage provider (library use)
* Unix support
* Read-only mode for safe vault access

## Work in progress

* Dropbox, Google Drive, OneDrive, S3 compatible and other cloud storages to work with without synchronizing with a local directory.

## Building

```shell
make build
```

This will build the whole project and put the release version of a binarry file to `target/release/` folder.

## Start Cryptomator

### Create a new vault

```shell
cryptomator --storage-path /path/to/your/storage/ create
```

This will ask you for a password for your storage and generate `masterkey.cryptomator` file.

### Unlock a vault

```shell
cryptomator --storage-path /path/to/your/storage/ unlock
```

This will ask you for a password for your storage, and if you provide the correct one the program starts an NFS server
with your unlocked vault:

```
Feb 22 17:11:18.855 INFO Unlocking the storage...
Feb 22 17:11:18.857 INFO Deriving keys...
Feb 22 17:11:24.166 INFO Keys derived!
Feb 22 17:11:24.167 INFO Storage unlocked!
Feb 22 17:11:24.167 INFO Starting NFS server...
Feb 22 17:11:24.167 INFO NFS server started on 127.0.0.1:11111
```

Now you can mount it:

```bash
  mkdir tmp
  mount_nfs -o nolocks,vers=3,tcp,rsize=131072,actimeo=120,port=11111,mountport=11111 tmp
```

### Using S3 storage

The CLI can use an S3-compatible backend when you pass `--filesystem-provider s3`.
S3 configuration is loaded from environment variables (or a `.env` file in the
working directory).

Environment variables:

* `S3_BUCKET` (required) -- name of the S3 bucket
* `S3_REGION` (required) -- AWS region name (e.g. `us-east-1`)
* `S3_PREFIX` (optional) -- key prefix inside the bucket
* `S3_ENDPOINT` (optional) -- custom endpoint URL for S3-compatible services
* `S3_FORCE_PATH_STYLE` (optional, `true`/`false`) -- use path-style addressing
* `S3_VALIDATE_BUCKET` (optional, `true`/`false`) -- verify bucket access on startup
* `S3_ACCESS_KEY` / `S3_SECRET_KEY` (optional; must be provided together)
* `S3_SESSION_TOKEN` (optional) -- for temporary credentials
* `S3_REQUEST_TIMEOUT_SECONDS` (optional, integer > 0) -- per-request timeout

Command examples:

```shell
S3_BUCKET=my-bucket S3_REGION=us-east-1 S3_ACCESS_KEY=AKIA... S3_SECRET_KEY=... \
  cryptomator --filesystem-provider s3 --storage-path vaults/demo create
```

```shell
# Or use a .env file in the current directory
cryptomator --filesystem-provider s3 --storage-path vaults/demo unlock
```

### Unlock a vault in read-only mode

To unlock a vault in read-only mode (preventing any modifications):

```shell
cryptomator --storage-path /path/to/your/storage unlock --read-only
```

When a vault is opened in read-only mode, write operations such as creating files, creating directories, removing files, copying, or moving will be blocked and return a `FileSystemError::ReadOnly`. This provides an additional layer of protection against accidental modifications when you only need to read from the vault.

For more advanced usage:

```shell
cryptomator --help
```

## Testing

```shell
make test
```

### S3 Integration Tests

S3 filesystem integration tests are gated by environment variables. Set these to enable the
roundtrip test against your S3-compatible endpoint:

> ⚠️ Do not commit these environment variables to source control, as they may contain secrets.

* `S3_TEST_ENDPOINT`
* `S3_TEST_BUCKET`
* `S3_TEST_ACCESS_KEY`
* `S3_TEST_SECRET_KEY`
* `S3_TEST_REGION` (optional, defaults to `us-east-1`)
* `S3_TEST_PREFIX` (optional)
* `S3_TEST_PATH_STYLE` (optional: `true`/`1`)
* `S3_TEST_SESSION_TOKEN` (optional)
