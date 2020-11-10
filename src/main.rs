use cryptomator::masterkey::MasterKey;

fn main() {
    let mp: MasterKey = MasterKey::from_file(String::from(
        "/Users/pr0n00gler/test_storage/masterkey.cryptomator",
    ))
    .unwrap();
    println!("{}", mp.primaryMasterKey)
}
