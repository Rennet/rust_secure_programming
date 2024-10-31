use aes::Aes256;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray
};
//use block_padding::Pkcs7;
//use aes::cipher;
use typenum::U32;
use hex;
use hex::FromHex;
use secrecy::ExposeSecret;


pub fn encrypt_db_entry(plaintext: String) -> String {

    let mut contents = plaintext.into_bytes();
    let mut plaintext = contents.clone();
    
    // Padding
    let padding_length = 16 - (plaintext.len() % 16);
    plaintext.extend(vec![padding_length as u8; padding_length]);
    //println!("{}", super::my_key::secret_key().expose_secret());

    // cipher
    let binding = super::my_key::secret_key();
    let secret_key = binding.expose_secret(); // Retrieve the secret key

    // Store it as a String
    let key_string: String = secret_key.clone(); // Clone to extend the lifetime

    let key = hex_to_generic_array(&key_string).expect("Failed to create key from hex input");

    let cipher = Aes256::new(&key); // Pass a reference to the GenericArray

    let mut blocks: Vec<GenericArray<u8, aes::cipher::consts::U16>> = plaintext
    .chunks_exact(16)
    .map(|chunk| GenericArray::clone_from_slice(chunk))
    .collect();

    // encrypting
    for block in &mut blocks {
        cipher.encrypt_block(block);
    }

    // Convert encrypted blocks back to a byte array
    let ciphertext: Vec<u8> = blocks.iter()
    .flat_map(|block| block.as_slice())
    .cloned().collect();

    // string output
    hex::encode(ciphertext).to_string()
}

pub fn decrypt_db_entry(ciphertext: String) -> String {
    // Read the encrypted file
    let encrypted_data = hex::decode(ciphertext.trim()).expect("Failed to decode hex text");
    
    // Cipher initialization
    // cipher
    let binding = super::my_key::secret_key();
    let secret_key = binding.expose_secret(); // Retrieve the secret key

    // Store it as a String
    let key_string: String = secret_key.clone(); // Clone to extend the lifetime

    let key = hex_to_generic_array(&key_string).expect("Failed to create key from hex input");

    let cipher = Aes256::new(&key); // Pass a reference to the GenericArray
    
    // Decrypting
    let mut blocks: Vec<GenericArray<u8, aes::cipher::consts::U16>> = encrypted_data
        .chunks_exact(16)
        .map(GenericArray::clone_from_slice)
        .collect();

    // Decrypt each block
    for block in &mut blocks {
        cipher.decrypt_block(block);
    }

    // Convert decrypted blocks back to a byte array
    let mut decrypted_data: Vec<u8> = blocks.iter()
        .flat_map(|block| block.as_slice())
        .cloned()
        .collect();
    
    // Remove padding
    let padding_length = *decrypted_data.last().unwrap();
    decrypted_data.truncate(decrypted_data.len() - padding_length as usize);

    //String result
    String::from_utf8(decrypted_data).expect("Decrypted data is not valid UTF-8")
}

pub fn hex_to_generic_array(input: &str) -> Option<GenericArray<u8, U32>> {
    match <[u8; 32]>::from_hex(input) {
        Ok(bytes) => Some(GenericArray::clone_from_slice(&bytes)),
        Err(_) => {
            eprintln!("Error: Input contains invalid hexadecimal characters.");
            None
        }
    }
}