use cryptomator::crypto::{Cryptor, MasterKey};
use cryptomator::cryptofs::CryptoFS;
use cryptomator::providers::LocalFS;

fn main() {
    let local_fs = LocalFS::new();
    let masterkey =
        MasterKey::from_file("tests/test_storage/masterkey.cryptomator", "12345678").unwrap();
    let cryptor = Cryptor::new(&masterkey);
    let crypto_fs = CryptoFS::new("d", &cryptor, local_fs).unwrap();
    let files = crypto_fs.read_dir("/kek/wow").unwrap();
    for f in files {
        println!("{}", f)
    }
    //crypto_fs.create_dir("/kek/wow").unwrap();
    //crypto_fs.dir_id_from_path("/kek/wow").unwrap();
}
