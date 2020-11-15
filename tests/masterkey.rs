use cryptomator::crypto;

const PATH_TO_MASTER_KEY: &str = "tests/test_storage/masterkey.cryptomator";
const DEFAULT_PASSWORD: &str = "12345678";

#[test]
fn test_master_key_from_file() {
    crypto::MasterKey::from_file(PATH_TO_MASTER_KEY, DEFAULT_PASSWORD).unwrap();
}
