use crate::cryptofs::{CryptoFS, FileSystem};
use fuse::{
    FileAttr, FileType, Filesystem as FuseFS, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request, FUSE_ROOT_ID,
};
use libc::ENOENT;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{Read, SeekFrom};
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
    free_inodes: Vec<u64>,
    inode_to_entry: HashMap<u64, PathBuf>,
    crypto_fs: CryptoFS<FS>,
    last_inode: u64,
}

impl<FS: FileSystem> FUSE<FS> {
    pub fn new(crypto_fs: CryptoFS<FS>) -> FUSE<FS> {
        let mut inode_to_entry: HashMap<u64, PathBuf> = HashMap::new();
        inode_to_entry.insert(FUSE_ROOT_ID, PathBuf::new());
        FUSE {
            free_inodes: vec![],
            inode_to_entry: inode_to_entry.clone(),
            crypto_fs,
            last_inode: 1,
        }
    }
}

impl<FS: FileSystem> FuseFS for FUSE<FS> {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        println!("LOOKUP {} {}", parent, name.to_str().unwrap());
        let entry_name = if let Some(e) = self.inode_to_entry.get(&parent) {
            e
        } else {
            reply.error(ENOENT);
            return;
        };
        let entry = if let Ok(m) = self.crypto_fs.metadata(entry_name.join(name)) {
            m
        } else {
            reply.error(ENOENT);
            return;
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
            perm: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
        };
        self.last_inode += 1;
        reply.entry(&TTL, &attr, 0);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        println!("GETATTR {}", ino);
        let entry_name = if let Some(e) = self.inode_to_entry.get(&ino) {
            e
        } else {
            reply.error(ENOENT);
            return;
        };
        let entry = self.crypto_fs.metadata(entry_name).unwrap();
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
            perm: 0,
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
        println!("READ {}", ino);
        let entry_name = if let Some(e) = self.inode_to_entry.get(&ino) {
            e
        } else {
            reply.error(ENOENT);
            return;
        };
        let mut f = self.crypto_fs.open_file(entry_name).unwrap();
        f.seek(SeekFrom::Start(offset as u64)).unwrap();
        let mut data = vec![0u8; _size as usize];
        if let Err(e) = f.read_exact(data.as_mut_slice()) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                reply.error(libc::EOF);
                return;
            }
        }
        reply.data(data.as_slice());
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        println!("READDIR {}", ino);
        let entry_name = if let Some(e) = self.inode_to_entry.get(&ino) {
            e.clone()
        } else {
            reply.error(ENOENT);
            return;
        };
        let entries = self.crypto_fs.read_dir(&entry_name).unwrap();
        for (i, entry) in entries.enumerate() {
            self.inode_to_entry
                .insert(self.last_inode + 1, entry_name.join(&entry.file_name));
            reply.add(
                self.last_inode + 1,
                (i + 1) as i64,
                match entry.metadata.is_file {
                    true => FileType::RegularFile,
                    false => FileType::Directory,
                },
                entry.file_name,
            );
            self.last_inode += 1;
        }
        reply.ok()
    }
}
