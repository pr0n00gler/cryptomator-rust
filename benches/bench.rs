use std::hint::black_box;
use std::io::Cursor;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use cryptomator::crypto::{
    Claims, Cryptor, MasterKey, Vault, FILE_CHUNK_CONTENT_PAYLOAD_LENGTH, FILE_CHUNK_LENGTH,
    FILE_HEADER_LENGTH,
};

const CHUNK_SIZES: [usize; 4] = [64, 1024, 16 * 1024, FILE_CHUNK_CONTENT_PAYLOAD_LENGTH];
const BENCH_CHUNK_NUMBER: u64 = 7;
const CONTENT_SIZES: [usize; 3] = [1024, 64 * 1024, 256 * 1024];

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

fn content_inputs() -> Vec<(usize, Vec<u8>)> {
    CONTENT_SIZES
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
            let mut output = vec![0u8; FILE_CHUNK_LENGTH];
            b.iter(|| {
                let len = cryptor
                    .encrypt_chunk(
                        &header_nonce,
                        &file_key,
                        BENCH_CHUNK_NUMBER,
                        chunk.as_slice(),
                        &mut output,
                    )
                    .expect("failed to encrypt chunk");
                black_box(&output[..len]);
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
            let mut encrypted = vec![0u8; FILE_CHUNK_LENGTH];
            let len = cryptor
                .encrypt_chunk(
                    &header_nonce,
                    &file_key,
                    BENCH_CHUNK_NUMBER,
                    plain.as_slice(),
                    &mut encrypted,
                )
                .expect("failed to encrypt chunk");
            encrypted.truncate(len);
            (size, encrypted)
        })
        .collect();

    let mut group = c.benchmark_group("decrypt_chunk");
    for (size, chunk) in &encrypted_inputs {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), chunk, |b, chunk| {
            let mut output = vec![0u8; FILE_CHUNK_LENGTH];
            b.iter(|| {
                let len = cryptor
                    .decrypt_chunk(
                        &header_nonce,
                        &file_key,
                        BENCH_CHUNK_NUMBER,
                        chunk.as_slice(),
                        &mut output,
                    )
                    .expect("failed to decrypt chunk");
                black_box(&output[..len]);
            });
        });
    }
    group.finish();
}

fn bench_encrypt_content(c: &mut Criterion) {
    let cryptor = create_cryptor();
    let inputs = content_inputs();

    let mut group = c.benchmark_group("encrypt_content");
    for (size, data) in &inputs {
        let expected_plain = *size;
        group.throughput(Throughput::Bytes(expected_plain as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(expected_plain),
            data,
            |b, data| {
                b.iter(|| {
                    let mut input = Cursor::new(data.as_slice());
                    let mut output =
                        Vec::with_capacity(data.len() + FILE_HEADER_LENGTH + FILE_CHUNK_LENGTH);
                    cryptor
                        .encrypt_content(&mut input, &mut output)
                        .expect("failed to encrypt content");
                    black_box(output);
                });
            },
        );
    }
    group.finish();
}

fn bench_decrypt_content(c: &mut Criterion) {
    let cryptor = create_cryptor();

    let encrypted_inputs: Vec<(usize, Vec<u8>)> = CONTENT_SIZES
        .iter()
        .map(|&size| {
            let plain = make_chunk_data(size);
            let mut encrypted =
                Vec::with_capacity(plain.len() + FILE_HEADER_LENGTH + FILE_CHUNK_LENGTH);
            cryptor
                .encrypt_content(&mut Cursor::new(plain.as_slice()), &mut encrypted)
                .expect("failed to prepare encrypted content");
            (size, encrypted)
        })
        .collect();

    let mut group = c.benchmark_group("decrypt_content");
    for (size, encrypted) in &encrypted_inputs {
        let expected_plain = *size;
        group.throughput(Throughput::Bytes(expected_plain as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(expected_plain),
            encrypted,
            |b, encrypted| {
                b.iter(|| {
                    let mut input = Cursor::new(encrypted.as_slice());
                    let mut output = Vec::with_capacity(expected_plain);
                    cryptor
                        .decrypt_content(&mut input, &mut output)
                        .expect("failed to decrypt content");
                    black_box(output);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_encrypt_chunk,
    bench_decrypt_chunk,
    bench_encrypt_content,
    bench_decrypt_content,
);
criterion_main!(benches);
