use cryptomator::crypto::{Cryptor, MasterKey};
use std::fs;

fn main() {
    let _master_key =
        MasterKey::from_file("tests/test_storage/masterkey.cryptomator", "12345678").unwrap();

    let cryptor = Cryptor::new(_master_key);

    let decrypted_filename = cryptor
        .decrypt_filename("fXQEfw6iSwP1esHbRznuVFZqv_LQFqNwC2r2LOQa-A==", b"")
        .unwrap();

    let encrypted_file = fs::File::open("tests/test_storage/d/HI/RW3L6XRAPFC2UCK5QY37Q2U552IRPE/fXQEfw6iSwP1esHbRznuVFZqv_LQFqNwC2r2LOQa-A==.c9r").unwrap();
    let decrypted_file = fs::File::create(decrypted_filename).unwrap();
    cryptor
        .decrypt_content(encrypted_file, decrypted_file)
        .unwrap();
}
