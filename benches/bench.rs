use std::iter;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use cryptomator::crypto;
use cryptomator::crypto::Cryptor;
use cryptomator::cryptofs::{CryptoFS, FileSystem};
use cryptomator::providers::MemoryFS;
use std::io::{Read, SeekFrom};

const PATH_TO_MASTER_KEY: &str = "tests/test_storage/masterkey.cryptomator";
const DEFAULT_PASSWORD: &str = "12345678";
const VFS_STORAGE_PATH: &str = "/";

const KB: usize = 1024;
const MB: usize = 1024 * KB;

fn crypto_fs_write(c: &mut Criterion) {
    let mk_file = std::fs::File::open(PATH_TO_MASTER_KEY).unwrap();
    let mk = crypto::MasterKey::from_reader(mk_file, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(mk);

    let local_fs = MemoryFS::new();
    let crypto_fs = CryptoFS::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let sizes = [10 * MB];

    let mut group = c.benchmark_group("crypto_write");
    for size in sizes.iter() {
        let random_data: Vec<u8> = (0..*size).map(|_| rand::random::<u8>()).collect();
        let mut bench_file = crypto_fs
            .create_file(format!("/bench#{}.dat", *size))
            .unwrap();

        group.throughput(Throughput::Bytes(random_data.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("crypto_write", random_data.len()),
            &random_data,
            |b, data| {
                b.iter(|| {
                    bench_file.write_all(data).unwrap();
                    bench_file.flush().unwrap();
                });
            },
        );
    }
    group.finish();
}

fn crypto_fs_read(c: &mut Criterion) {
    let mk_file = std::fs::File::open(PATH_TO_MASTER_KEY).unwrap();
    let mk = crypto::MasterKey::from_reader(mk_file, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(mk);

    let local_fs = MemoryFS::new();
    let crypto_fs = CryptoFS::new(VFS_STORAGE_PATH, cryptor, local_fs).unwrap();

    let random_data: Vec<u8> = (0..10 * MB).map(|_| rand::random::<u8>()).collect();
    let mut bench_file = crypto_fs.create_file("/bench.dat").unwrap();
    bench_file.write_all(&random_data).unwrap();
    bench_file.flush().unwrap();

    let sizes = [5 * MB];
    let mut group = c.benchmark_group("crypto_read");
    for size in sizes.iter() {
        let mut f = crypto_fs.open_file("/bench.dat").unwrap();
        let mut data: Vec<u8> = vec![0; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_function(BenchmarkId::new("crypto_read", *size), |b| {
            b.iter(|| {
                let _ = f.read(&mut data).unwrap();
                f.seek(SeekFrom::Start(0)).unwrap();
            });
        });
    }
    group.finish();
}

fn crypto_encrypt_chunk(c: &mut Criterion) {
    let mk_file = std::fs::File::open(PATH_TO_MASTER_KEY).unwrap();
    let mk = crypto::MasterKey::from_reader(mk_file, DEFAULT_PASSWORD).unwrap();
    let cryptor = crypto::Cryptor::new(mk);

    let sizes = [32 * KB];

    let mut group = c.benchmark_group("crypto_encrypt_chunk");
    for size in sizes.iter() {
        let random_data: Vec<u8> = (0..*size).map(|_| rand::random::<u8>()).collect();
        let file_key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let nonce: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();

        group.throughput(Throughput::Bytes(random_data.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("crypto_encrypt_chunk", random_data.len()),
            &random_data,
            |b, data| {
                b.iter(|| cryptor.encrypt_chunk(&nonce, &file_key, 1, data).unwrap());
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    crypto_fs_write,
    crypto_fs_read,
    crypto_encrypt_chunk
);
criterion_main!(benches);
