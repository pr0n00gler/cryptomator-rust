use cryptomator::crypto::{MasterKey, Cryptor};

fn main() {
    let _master_key = MasterKey::from_file("tests/test_storage/masterkey.cryptomator", "12345678").unwrap();

    let cryptor = Cryptor::new(_master_key);

    let decrypted_filename = cryptor.decrypt_filename("gBmHXW5KGoOJ2UgC-a9JbhdBiyTQJdRmmjEwm2nCDwmXuCnknFK1UYz_", "").unwrap();
    println!("{}", String::from_utf8(decrypted_filename).unwrap());
}