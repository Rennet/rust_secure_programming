#![no_main]
use libfuzzer_sys::fuzz_target;
use rust_secure_programming::file_deletion;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fuzz_target!(|data: &[u8]| {
    //pub fn encrypt_db_entry(plaintext: String) -> String {

        let contents = data.into_bytes();
        let mut plaintext = contents.clone();
        
        // Padding
        let padding_length = 16 - (plaintext.len() % 16);
        plaintext.extend(vec![padding_length as u8; padding_length]);
    
        // cipher
        let binding = super::my_key::secret_key();
        // Store it as a String
        //let key_string: String = secret_key.clone(); // Clone to extend the lifetime
    
        //let key = hex_to_generic_array(&key_string).expect("Failed to create key from hex input");
        let key = GenericArray::from_slice(binding.expose_secret());
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
});
