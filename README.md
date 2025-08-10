![CI](https://github.com/programmer10110/cryptomator-rust/actions/workflows/ci.yml/badge.svg)

# Cryptomator Rust

This is pure-Rust implementation of the [Cryptomator](cryptomator.org) project.

Right now this is a minimal command-line program that unlocks vaults of vault format 7.
After the unlock the vault content can then be accessed via an embedded WebDAV server.

## Disclaimer

This project is in an early stage and not ready for production use. We recommend to use it only for testing and
evaluation purposes.

## Features

* Full support of the original Cryptomator vaults of vault format 7.
* Works with local vaults
* Unlocked content can be accessed via an embedded WebDav or NFS server;
* Windows/Unix support

## Work in progress

* FUSE/Dokan support to mount vaults as a virtual filesystem
* Dropbox, Google Drive, OneDrive and other cloud storages to work with without synchronize with a local directory
* GUI
* Log coverage

## Building

```shell
make build-release
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

For more advanced usage:

```shell
cryptomator --help
```

## Testing

```shell
make test
```