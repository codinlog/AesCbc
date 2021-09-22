use openssl::base64;
use openssl::symm::{Cipher, Crypter, Mode};

const KEY: &[u8; 16] = b"1234567890abcdef";
const IV: &[u8; 16] = b"1234567890abcdef";
fn main() {
    let hello =r#"{"id": 2,"name": "分区:美食侦探", "toast": "将减少相似内容推荐" },"#;
    convert_string_to_aes_128_cbc_base64(hello);
    convert_base64_aes_128_cbc_to_string("jIk/wjTf0kXQxQ8xCZ5quEvN2C9MbCmzpJJYwz6HJRh29hbE2xLfISuK5k1i36SqJP1iF/XYHrW0wNpuVN2RYTufRCBhFTNTw+oNxpJZhvtidTIRJV/h5iDOOcIdk6Pa");
}

fn convert_string_to_aes_128_cbc_base64(src: &str) {
    let mut encrypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Encrypt, KEY, Some(IV)).unwrap();
    let block_size = Cipher::aes_128_cbc().block_size();
    let mut ciphertext = vec![0; src.len() + block_size];
    let mut count = encrypter.update(src.as_ref(), &mut ciphertext).unwrap();
    count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count);
    println!("{}", base64::encode_block(&*ciphertext));
}

fn convert_base64_aes_128_cbc_to_string(src: &str) {
    // Create a cipher context for decryption.
    let source = base64::decode_block(src).unwrap();
    let mut decrypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Decrypt, KEY, Some(IV)).unwrap();
    let block_size = Cipher::aes_128_cbc().block_size();
    let mut plaintext = vec![0; source.len() + block_size];

    // Decrypt 2 chunks of ciphertexts successively.
    let mut count = decrypter.update(&source, &mut plaintext).unwrap();
    count += decrypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count);
    println!("{}", String::from_utf8_lossy(&*plaintext));
}
