use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use cryptomator::crypto::{Claims, Cryptor, MasterKey, Vault, FILE_CHUNK_CONTENT_PAYLOAD_LENGTH};

const CHUNK_SIZES: [usize; 4] = [64, 1024, 16 * 1024, FILE_CHUNK_CONTENT_PAYLOAD_LENGTH];
const BENCH_CHUNK_NUMBER: u64 = 7;

fn create_cryptor() -> Cryptor {
    let master_key = MasterKey {
        primary_master_key: [0x11; 32],
        hmac_master_key: [0x22; 32],
    };

    let vault = Vault {
        master_key,
        claims: Claims::default(),
    };

    Cryptor::new(vault)
}

fn make_chunk_data(size: usize) -> Vec<u8> {
    vec![0xA5; size]
}

fn chunk_inputs() -> Vec<(usize, Vec<u8>)> {
    CHUNK_SIZES
        .iter()
        .map(|&size| (size, make_chunk_data(size)))
        .collect()
}

fn bench_encrypt_chunk(c: &mut Criterion) {
    let cryptor = create_cryptor();
    let file_header = cryptor.create_file_header();
    let header_nonce = file_header.nonce;
    let file_key = file_header.payload.content_key;

    let inputs = chunk_inputs();
    let mut group = c.benchmark_group("encrypt_chunk");
    for (size, chunk) in &inputs {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), chunk, |b, chunk| {
            b.iter(|| {
                let encrypted = cryptor
                    .encrypt_chunk(&header_nonce, &file_key, BENCH_CHUNK_NUMBER, chunk.as_slice())
                    .expect("failed to encrypt chunk");
                black_box(encrypted);
            });
        });
    }
    group.finish();
}

fn bench_decrypt_chunk(c: &mut Criterion) {
    let cryptor = create_cryptor();
    let file_header = cryptor.create_file_header();
    let header_nonce = file_header.nonce;
    let file_key = file_header.payload.content_key;

    let encrypted_inputs: Vec<(usize, Vec<u8>)> = CHUNK_SIZES
        .iter()
        .map(|&size| {
            let plain = make_chunk_data(size);
            let encrypted = cryptor
                .encrypt_chunk(&header_nonce, &file_key, BENCH_CHUNK_NUMBER, plain.as_slice())
                .expect("failed to encrypt chunk");
            (size, encrypted)
        })
        .collect();

    let mut group = c.benchmark_group("decrypt_chunk");
    for (size, chunk) in &encrypted_inputs {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), chunk, |b, chunk| {
            b.iter(|| {
                let decrypted = cryptor
                    .decrypt_chunk(&header_nonce, &file_key, BENCH_CHUNK_NUMBER, chunk.as_slice())
                    .expect("failed to decrypt chunk");
                black_box(decrypted);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encrypt_chunk, bench_decrypt_chunk);
criterion_main!(benches);
