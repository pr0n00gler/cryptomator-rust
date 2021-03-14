use crate::cryptofs::{unix_error_code_from_filesystem_error, CryptoFS, FileSystem};
use failure::AsFail;
use fuse::{
    FileAttr, FileType, Filesystem as FuseFS, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyStatfs, ReplyWrite, Request, FUSE_ROOT_ID,
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
    free_inodes: Vec<u64>,
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
            free_inodes: vec![],
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
                reply.error(unix_error_code_from_filesystem_error(e));
                return;
            }
        };

        let inode = if let Some(i) = self.free_inodes.pop() {
            i
        } else {
            self.last_inode += 1;
            self.last_inode
        };
        let attr = FileAttr {
            ino: inode,
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

        self.inode_to_entry.insert(inode, entry_name.join(name));
        self.entry_to_inode.insert(entry_name.join(name), inode);

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
                reply.error(unix_error_code_from_filesystem_error(e));
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

    fn mkdir(&mut self, _req: &Request, parent: u64, name: &OsStr, _mode: u32, reply: ReplyEntry) {
        let parent_path = if let Some(p) = self.inode_to_entry.get(&parent) {
            p
        } else {
            error!("Inode {} does not exist", parent);
            reply.error(ENOENT);
            return;
        };
        let entry_path = parent_path.join(name);

        if let Some(e) = self.crypto_fs.create_dir_all(&entry_path).err() {
            error!(
                "Failed to create dir {}: {}",
                entry_path.display(),
                e.as_fail()
            );
            reply.error(unix_error_code_from_filesystem_error(e));
            return;
        }

        let metadata = match self.crypto_fs.metadata(&entry_path) {
            Ok(m) => m,
            Err(e) => {
                error!(
                    "Failed to get metadata of a file {}: {}",
                    entry_path.display(),
                    e.as_fail()
                );
                reply.error(unix_error_code_from_filesystem_error(e));
                return;
            }
        };

        let inode = if let Some(i) = self.free_inodes.pop() {
            i
        } else {
            self.last_inode += 1;
            self.last_inode
        };

        let attr = FileAttr {
            ino: inode,
            size: metadata.len,
            blocks: 0,
            atime: systime_to_timespec(metadata.accessed),
            mtime: systime_to_timespec(metadata.modified),
            ctime: systime_to_timespec(metadata.created),
            crtime: Timespec::new(0, 0),
            kind: FileType::Directory,
            perm: 0o777,
            nlink: 0,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
        };

        self.inode_to_entry.insert(inode, entry_path.clone());
        self.entry_to_inode.insert(entry_path, inode);

        reply.entry(&TTL, &attr, 0);
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = if let Some(p) = self.inode_to_entry.get(&parent) {
            p
        } else {
            error!("Inode {} does not exist", parent);
            reply.error(ENOENT);
            return;
        };
        let entry_path = parent_path.join(name);

        if let Some(e) = self.crypto_fs.remove_file(&entry_path).err() {
            error!(
                "Failed to remove file {}: {}",
                entry_path.display(),
                e.as_fail()
            );
            reply.error(unix_error_code_from_filesystem_error(e));
            return;
        }

        if let Some(inode) = self.entry_to_inode.get(&entry_path) {
            self.inode_to_entry.remove(inode);
            self.free_inodes.push(*inode);
            self.entry_to_inode.remove(&entry_path);
        }

        reply.ok();
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = if let Some(p) = self.inode_to_entry.get(&parent) {
            p
        } else {
            error!("Inode {} does not exist", parent);
            reply.error(ENOENT);
            return;
        };
        let entry_path = parent_path.join(name);
        if let Some(e) = self.crypto_fs.remove_dir(&entry_path).err() {
            error!(
                "Failed to remove dir {}: {}",
                entry_path.display(),
                e.as_fail()
            );
            reply.error(unix_error_code_from_filesystem_error(e));
            return;
        }

        if let Some(inode) = self.entry_to_inode.get(&entry_path) {
            self.inode_to_entry.remove(inode);
            self.free_inodes.push(*inode);
            self.entry_to_inode.remove(&entry_path);
        }

        reply.ok()
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEmpty,
    ) {
        let parent_path = if let Some(p) = self.inode_to_entry.get(&parent) {
            p
        } else {
            error!("Inode {} does not exist", parent);
            reply.error(ENOENT);
            return;
        };
        let entry_path = parent_path.join(name);
        let entry_metadata = match self.crypto_fs.metadata(&entry_path) {
            Ok(m) => m,
            Err(e) => {
                error!(
                    "Failed to get metadata of an entry {}: {}",
                    entry_path.display(),
                    e.as_fail()
                );
                reply.error(ENOENT);
                return;
            }
        };

        let new_parent_path = if let Some(p) = self.inode_to_entry.get(&newparent) {
            p
        } else {
            error!("Inode {} does not exist", newparent);
            reply.error(ENOENT);
            return;
        };
        let new_entry_path = new_parent_path.join(newname);

        if entry_metadata.is_dir {
            if let Some(e) = self.crypto_fs.move_dir(&entry_path, &new_entry_path).err() {
                error!(
                    "Failed to rename dir {}: {}",
                    entry_path.display(),
                    e.as_fail()
                );
                reply.error(unix_error_code_from_filesystem_error(e));
                return;
            }
        } else if let Some(e) = self.crypto_fs.move_file(&entry_path, &new_entry_path).err() {
            error!(
                "Failed to rename file {}: {}",
                entry_path.display(),
                e.as_fail()
            );
            reply.error(unix_error_code_from_filesystem_error(e));
            return;
        }

        if let Some(inode) = self.entry_to_inode.get(&entry_path) {
            self.inode_to_entry.insert(*inode, new_entry_path);
        }

        reply.ok();
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
                reply.error(unix_error_code_from_filesystem_error(e));
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
                reply.error(unix_error_code_from_filesystem_error(e));
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
                reply.error(unix_error_code_from_filesystem_error(e));
                return;
            }
        };
        for (i, entry) in entries.enumerate().skip(offset as usize) {
            let inode: u64;

            if let Some(i) = self.entry_to_inode.get(&entry_name.join(&entry.file_name)) {
                inode = *i;
            } else {
                inode = if let Some(i) = self.free_inodes.pop() {
                    i
                } else {
                    self.last_inode += 1;
                    self.last_inode
                };
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

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        let stats = self.crypto_fs.stats("/").unwrap();
        reply.statfs(
            stats.total_space / stats.allocation_granularity,
            stats.free_space / stats.allocation_granularity,
            stats.available_space / stats.allocation_granularity,
            self.inode_to_entry.len() as u64,
            (usize::MAX - self.inode_to_entry.len() + self.free_inodes.len()) as u64,
            stats.allocation_granularity as u32,
            255,
            stats.allocation_granularity as u32,
        );
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
        let f = match self.crypto_fs.create_file(&entry_path) {
            Ok(f) => f,
            Err(e) => {
                error!(
                    "Failed to create file {}: {}",
                    entry_path.display(),
                    e.as_fail()
                );
                reply.error(unix_error_code_from_filesystem_error(e));
                return;
            }
        };

        let inode = if let Some(i) = self.free_inodes.pop() {
            i
        } else {
            self.last_inode += 1;
            self.last_inode
        };

        let attr = FileAttr {
            ino: inode,
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

        self.inode_to_entry.insert(inode, entry_path.clone());
        self.entry_to_inode.insert(entry_path, inode);

        reply.created(&TTL, &attr, 0, 0, _flags);
    }
}
