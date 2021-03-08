use crate::cryptofs::{CryptoFS, FileSystem};
use failure::AsFail;
use fuse::{
    FileAttr, FileType, Filesystem as FuseFS, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEntry, ReplyStatfs, ReplyWrite, Request, FUSE_ROOT_ID,
};
use libc::{EIO, ENOENT, EOF};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{Read, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use time::Timespec;

const TTL: Timespec = Timespec { sec: 1, nsec: 0 };

fn systime_to_timespec(s: SystemTime) -> Timespec {
    Timespec::new(
        s.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64,
        //TODO: nsec
        0,
    )
}

pub struct FUSE<FS: FileSystem> {
    inode_to_entry: HashMap<u64, PathBuf>,
    entry_to_inode: HashMap<PathBuf, u64>,
    crypto_fs: CryptoFS<FS>,
    last_inode: u64,
}

impl<FS: FileSystem> FUSE<FS> {
    pub fn new(crypto_fs: CryptoFS<FS>) -> FUSE<FS> {
        let mut inode_to_entry: HashMap<u64, PathBuf> = HashMap::new();
        inode_to_entry.insert(FUSE_ROOT_ID, std::path::Path::new("/").to_path_buf());

        let mut entry_to_inode: HashMap<PathBuf, u64> = HashMap::new();
        entry_to_inode.insert(std::path::Path::new("/").to_path_buf(), FUSE_ROOT_ID);

        FUSE {
            inode_to_entry,
            entry_to_inode,
            crypto_fs,
            last_inode: 1,
        }
    }
}

impl<FS: FileSystem> FuseFS for FUSE<FS> {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let entry_name = if let Some(e) = self.inode_to_entry.get(&parent) {
            e.clone()
        } else {
            error!("Inode {} does not exist", parent);
            reply.error(ENOENT);
            return;
        };
        let entry = match self.crypto_fs.metadata(entry_name.join(name)) {
            Ok(m) => m,
            Err(e) => {
                error!(
                    "Failed to get metadata of a file {}: {}",
                    entry_name.join(name).display(),
                    e.as_fail()
                );
                reply.error(ENOENT);
                return;
            }
        };
        let attr = FileAttr {
            ino: self.last_inode + 1,
            size: entry.len,
            blocks: 0,
            atime: systime_to_timespec(entry.accessed),
            mtime: systime_to_timespec(entry.modified),
            ctime: systime_to_timespec(entry.created),
            crtime: Timespec::new(0, 0),
            kind: match entry.is_file {
                true => FileType::RegularFile,
                false => FileType::Directory,
            },
            perm: 0o777,
            nlink: 0,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
        };
        self.last_inode += 1;
        self.inode_to_entry
            .insert(self.last_inode, entry_name.join(name));
        self.entry_to_inode
            .insert(entry_name.join(name), self.last_inode);
        reply.entry(&TTL, &attr, 0);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        let entry_name = if let Some(e) = self.inode_to_entry.get(&ino) {
            e
        } else {
            error!("Inode {} does not exist", ino);
            reply.error(ENOENT);
            return;
        };
        let entry = match self.crypto_fs.metadata(entry_name) {
            Ok(m) => m,
            Err(e) => {
                error!(
                    "Failed to get metadata of a file {}: {}",
                    entry_name.display(),
                    e.as_fail()
                );
                reply.error(ENOENT);
                return;
            }
        };
        let attr = FileAttr {
            ino,
            size: entry.len,
            blocks: 0,
            atime: systime_to_timespec(entry.accessed),
            mtime: systime_to_timespec(entry.modified),
            ctime: systime_to_timespec(entry.created),
            crtime: Timespec::new(0, 0),
            kind: match entry.is_file {
                true => FileType::RegularFile,
                false => FileType::Directory,
            },
            perm: 0o777,
            nlink: 0,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
        };
        reply.attr(&TTL, &attr);
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        _size: u32,
        reply: ReplyData,
    ) {
        let entry_name = if let Some(e) = self.inode_to_entry.get(&ino) {
            e
        } else {
            error!("Inode {} does not exist", ino);
            reply.error(ENOENT);
            return;
        };
        let mut f = match self.crypto_fs.open_file(entry_name) {
            Ok(f) => f,
            Err(e) => {
                error!(
                    "Failed to open file {}: {}",
                    entry_name.display(),
                    e.as_fail()
                );
                reply.error(ENOENT);
                return;
            }
        };
        if let Some(e) = f.seek(SeekFrom::Start(offset as u64)).err() {
            error!("Failed to seek file: {}", e.as_fail());
            reply.error(EIO);
            return;
        }
        let mut data = vec![0u8; _size as usize];
        match f.read(data.as_mut_slice()) {
            Ok(n) => reply.data(&data.as_slice()[..n]),
            Err(e) => {
                error!("Failed to read file: {}", e.as_fail());
                reply.error(EOF);
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let entry_name = if let Some(e) = self.inode_to_entry.get(&ino) {
            e.clone()
        } else {
            error!("Inode {} does not exist", ino);
            reply.error(ENOENT);
            return;
        };
        let entries = match self.crypto_fs.read_dir(&entry_name) {
            Ok(e) => e,
            Err(e) => {
                error!(
                    "Failed to read dir {}: {}",
                    entry_name.display(),
                    e.as_fail()
                );
                reply.error(ENOENT);
                return;
            }
        };
        for (i, entry) in entries.enumerate().skip(offset as usize) {
            let inode: u64;

            if let Some(i) = self.entry_to_inode.get(&entry_name.join(&entry.file_name)) {
                inode = *i;
            } else {
                inode = self.last_inode + 1;
                self.inode_to_entry
                    .insert(inode, entry_name.join(&entry.file_name));
                self.entry_to_inode
                    .insert(entry_name.join(&entry.file_name), inode);
                self.last_inode += 1;
            }
            reply.add(
                inode,
                (i + 1) as i64,
                match entry.metadata.is_file {
                    true => FileType::RegularFile,
                    false => FileType::Directory,
                },
                entry.file_name,
            );
        }
        reply.ok()
    }

    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _flags: u32,
        reply: ReplyWrite,
    ) {
        let entry_name = if let Some(e) = self.inode_to_entry.get(&ino) {
            e
        } else {
            error!("Inode {} does not exist", ino);
            reply.error(ENOENT);
            return;
        };
        let mut f = match self.crypto_fs.open_file(entry_name) {
            Ok(f) => f,
            Err(e) => {
                error!(
                    "Failed to open file {}: {}",
                    entry_name.display(),
                    e.as_fail()
                );
                reply.error(ENOENT);
                return;
            }
        };
        if let Some(e) = f.seek(SeekFrom::Start(offset as u64)).err() {
            error!("Failed to seek file: {}", e.as_fail());
            reply.error(EIO);
            return;
        }
        match f.write(data) {
            Ok(n) => reply.written(n as u32),
            Err(e) => {
                error!("Failed to read file: {}", e.as_fail());
                reply.error(EOF);
            }
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _flags: u32,
        reply: ReplyCreate,
    ) {
        let parent_path = if let Some(p) = self.inode_to_entry.get(&parent) {
            p
        } else {
            error!("Inode {} does not exist", parent);
            reply.error(ENOENT);
            return;
        };
        let entry_path = parent_path.join(name);
        let f = self.crypto_fs.create_file(entry_path).unwrap();
        let attr = FileAttr {
            ino: self.last_inode + 1,
            size: f.metadata().unwrap().len,
            blocks: 0,
            atime: systime_to_timespec(f.metadata().unwrap().accessed),
            mtime: systime_to_timespec(f.metadata().unwrap().modified),
            ctime: systime_to_timespec(f.metadata().unwrap().created),
            crtime: Timespec::new(0, 0),
            kind: FileType::RegularFile,
            perm: 0o777,
            nlink: 0,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
        };
        reply.created(&TTL, &attr, 0, 0, _flags);
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        reply.statfs(0, 1000000000000, 10000000000000, 0, 0, 512, 255, 0);
    }
}
