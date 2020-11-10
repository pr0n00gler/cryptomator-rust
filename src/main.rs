use cryptomator::masterkey::MasterKey;

fn main() {
    let _master_key = MasterKey::from_file("tests/test_storage/masterkey.cryptomator", "12345678").unwrap();
    println!("done")
}
