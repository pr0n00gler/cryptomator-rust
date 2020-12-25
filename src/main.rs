use cryptomator::crypto::{Cryptor, MasterKey};
use cryptomator::cryptofs::{CryptoFS, CryptoFSFile};
use cryptomator::providers::LocalFS;
use std::io::{Read, Write};

fn main() {
    let local_fs = LocalFS::new();
    let masterkey =
        MasterKey::from_file("tests/test_storage/masterkey.cryptomator", "12345678").unwrap();
    let cryptor = Cryptor::new(&masterkey);
    let crypto_fs = CryptoFS::new("tests/test_storage/d", &cryptor, &local_fs).unwrap();
    let files = crypto_fs.read_dir("/").unwrap();
    for f in files {
        println!("{}", f)
    }
    let lorem_ipsum_real = cryptor.encrypt_filename("lorem-ipsum.pdf", &[]).unwrap();
    let root_folder = crypto_fs.real_path_from_dir_id(&[]).unwrap();
    let mut f = CryptoFSFile::open(
        (root_folder + "/" + lorem_ipsum_real.as_str() + ".c9r").as_str(),
        &cryptor,
        &local_fs,
    )
    .unwrap();
    let size = f.get_file_size().unwrap();
    let mut bytes: Vec<u8> = vec![];
    let read_bytes = f.read_to_end(&mut bytes).unwrap();
    println!("size={}, read_bytes={}", size, read_bytes);
    let mut o = std::fs::File::create("kek.pdf").unwrap();
    o.write_all(bytes.as_slice()).unwrap();
    //crypto_fs.create_dir("/kek/wow").unwrap();
    //crypto_fs.dir_id_from_path("/kek/wow").unwrap();
}
