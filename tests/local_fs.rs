use cryptomator::cryptofs::{FileSystem, OpenOptions};
use cryptomator::providers::LocalFs;
use std::fs;
use std::path::{Path, PathBuf};

fn temp_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!("cryptomator-localfs-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    root
}

fn cleanup(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

#[cfg(unix)]
#[test]
fn local_fs_rejects_symlinked_file() {
    let root = temp_root();
    let target = root.join("target.txt");
    fs::write(&target, b"secret").unwrap();
    let link = root.join("link.txt");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let fs = LocalFs::new();
    let err = fs.open_file(&link, OpenOptions::new()).unwrap_err();
    assert!(err.to_string().contains("Symlink rejected"));

    cleanup(&root);
}

#[cfg(unix)]
#[test]
fn local_fs_rejects_symlinked_directory_component() {
    let root = temp_root();
    let target_dir = root.join("target");
    fs::create_dir(&target_dir).unwrap();
    fs::write(target_dir.join("file.txt"), b"secret").unwrap();
    let link_dir = root.join("linked-dir");
    std::os::unix::fs::symlink(&target_dir, &link_dir).unwrap();

    let fs = LocalFs::new();
    let err = fs
        .open_file(link_dir.join("file.txt"), OpenOptions::new())
        .unwrap_err();
    assert!(err.to_string().contains("Symlink rejected"));

    cleanup(&root);
}

#[cfg(unix)]
#[test]
fn local_fs_rejects_symlinked_ancestor_on_create() {
    let root = temp_root();
    let target_dir = root.join("target");
    fs::create_dir(&target_dir).unwrap();
    let link_dir = root.join("linked-ancestor");
    std::os::unix::fs::symlink(&target_dir, &link_dir).unwrap();

    let fs = LocalFs::new();
    let err = fs.create_file(link_dir.join("new.txt")).unwrap_err();
    assert!(err.to_string().contains("Symlink rejected"));

    cleanup(&root);
}
