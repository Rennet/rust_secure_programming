use aes::Aes256;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray
};
use std::fs;
use std::path::PathBuf;
use std::fs::File;
use std::io::{self, Write};
//use block_padding::Pkcs7;
//use aes::cipher;
use typenum::U32;
//use redb::{Database, ReadableTable, TableDefinition};


pub fn file_encryption(file_path: PathBuf, key: GenericArray<u8, U32>) -> io::Result<()> {

    // file name
    let file_name = &file_path.file_stem().unwrap();
    let new_file_name = format!("{}{}", file_name.to_str().unwrap(), ".encrypted.rt");
    let contents = fs::read_to_string(file_path.clone())
    .expect("Should have been able to read the file");
    let mut plaintext = contents.clone().into_bytes();
    
    // Padding
    let padding_length = 16 - (plaintext.len() % 16);
    plaintext.extend(vec![padding_length as u8; padding_length]);
    
    
    // cipher
    let cipher = Aes256::new(&key);
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
    
    println!("{}",new_file_name);
    
    // create output file
    let mut file = File::create(&new_file_name)?;
    file.write_all(&ciphertext)?;
    drop(file_path);
    drop(file);
    Ok(())
}

pub fn file_decryption(file_path: PathBuf, key: GenericArray<u8, U32>) -> io::Result<()> {
    // File name for decrypted output
    let file_stem = file_path.file_stem().unwrap();
    let file_stem_str = file_stem.to_str().unwrap();
    println!("file_stem_str: {}",file_stem_str);
    
    // Remove the ".encrypted.rt" from the stem if it exists
    let new_file_stem = file_stem_str.trim_end_matches(".encrypted");
    println!("new_file_stem: {}",new_file_stem);

    // Create the new file name with ".decrypted.txt" extension
    let new_file_name = format!("{}", new_file_stem,);
    println!("new_file_name: {}",new_file_name);
    
    // Read the encrypted file
    let encrypted_data = fs::read(&file_path)?;
    
    // Cipher initialization
    let cipher = Aes256::new(&key);
    
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

    // Create output file
    let mut file = File::create(&new_file_name)?;
    file.write_all(&decrypted_data)?;

    Ok(())
}