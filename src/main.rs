mod masterkey;

fn main() {
    let mp: masterkey::masterkey::MasterKey = masterkey::masterkey::MasterKey::from_file(String::from("/Users/pr0n00gler/test_storage/masterkey.cryptomator")).unwrap();
    println!("{}", mp.primaryMasterKey)
}
