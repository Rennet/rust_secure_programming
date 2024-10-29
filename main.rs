use aes::Aes256;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray
};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::path::Path;
use std::fs::File;
use std::io::{self, Write};
use block_padding::Pkcs7;
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use typenum::U32;
use hex;

fn main() -> io::Result<()> {

    let args: Vec<String> = env::args().collect();
    dbg!(&args);
    let current_dir = env::current_dir().expect("Failed to get current directory");
    let file_path = PathBuf::from(&current_dir);
    //println!("Current directory: {:?}", current_dir);
    /*
    arg1 - function (help, encrypt, decrypt)
    arg2 - file
    arg3 - key - must be 32 bytes
    */

    if args.len() > 1 && args[1] == "help" {
        println!("To use this software, use secure.exe <function> <file_path> <key>");
        println!("Key size must be 32 bytes");
        println!("If key is not entered, it will be generated randomly and given to you as a plaintext.");
        println!("If user is authenticated then key will be tied to authentication, unless specified differently");
        println!("---");
        println!("---");
        println!("---");
        println!("---");
    }

    if args.len() > 1 && args[1] == "encrypt" {
        if args.len() > 2 {
            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&args[2]);

            let key = GenericArray::from([0u8; 32]);
            file_encryption(file_path, key)?;
        }
    }

    if args.len() > 1 && args[1] == "decrypt" {
        if args.len() > 2 {
            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&args[2]);
            
            let key = GenericArray::from([0u8; 32]);
            file_decryption(file_path, key)?;
        }
    }

    Ok(())
}
    
    
    // ENCRYPTION/DECRYPTION --------------------------------
    /*
    
    1. Implement AES for Encryption
    2. Implement AES for Decryption
    3. Memory in key for guest user, Memory saved for authenticated user
    4. Secure Original File Deletion after encryption 
    
- Library 
*/
fn file_encryption(file_path: PathBuf, key: GenericArray<u8, U32>) -> io::Result<()> {

    // file name
    let file_name = &file_path.file_stem().unwrap();
    let new_file_name = format!("{}{}", file_name.to_str().unwrap(), ".encrypted.rt");
    let contents = fs::read_to_string(file_path)
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

    // create new directory
    let new_directory_name = "encrypted";
    fs::create_dir_all(new_directory_name)?;
    let new_file_path = Path::new(new_directory_name).join(new_file_name);

    // create output file
    let mut file = File::create(&new_file_path)?;
    file.write_all(&ciphertext)?;
    Ok(())
}

fn file_decryption(file_path: PathBuf, key: GenericArray<u8, U32>) -> io::Result<()> {
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

    // Create output directory
    let new_directory_name = "decrypted";
    fs::create_dir_all(new_directory_name)?;
    let new_file_path = Path::new(new_directory_name).join(new_file_name);

    // Create output file
    let mut file = File::create(&new_file_path)?;
    file.write_all(&decrypted_data)?;

    Ok(())
}
