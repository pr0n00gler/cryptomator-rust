use cryptomator::crypto::{MasterKey, Cryptor};
use std::fs;

fn main() {
    let _master_key = MasterKey::from_file("tests/test_storage/masterkey.cryptomator", "12345678").unwrap();

    let cryptor = Cryptor::new(_master_key);

    let decrypted_filename = cryptor.decrypt_filename("gBmHXW5KGoOJ2UgC-a9JbhdBiyTQJdRmmjEwm2nCDwmXuCnknFK1UYz_", b"").unwrap();
    println!("{}", String::from_utf8(decrypted_filename).unwrap());

    let file = fs::read("tests/test_storage/d/HI/RW3L6XRAPFC2UCK5QY37Q2U552IRPE/gBmHXW5KGoOJ2UgC-a9JbhdBiyTQJdRmmjEwm2nCDwmXuCnknFK1UYz_.c9r").unwrap();
    println!("File size: {}", file.len());

    let header = Vec::from(&file[..88]);
    let file_header = cryptor.decrypt_file_header(header).unwrap();
    println!("{:?}", file_header.payload.reserved);

    let content = cryptor.decrypt_chunk(file_header.nonce.as_ref(),
                                        file_header.payload.content_key.as_ref(),
                                        0, Vec::from(&file[88..])).unwrap();

    println!("{:?}", content)
}