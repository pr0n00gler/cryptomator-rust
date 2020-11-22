use cryptomator::cryptofs::CryptoFS;
use cryptomator::providers::LocalFS;

fn main() {
    let local_fs = LocalFS::new();
    let crypto_fs = CryptoFS::new(
        "tests/test_storage/d",
        "tests/test_storage/masterkey.cryptomator",
        "12345678",
        local_fs,
    )
    .unwrap();
    let files = crypto_fs.read_dir("/").unwrap();
    for f in files {
        println!("{}", f)
    }
}
