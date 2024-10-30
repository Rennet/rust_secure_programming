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
//use block_padding::Pkcs7;
//use aes::cipher;
use typenum::U32;
//use hex;
use hex::FromHex;
use std::fs::{OpenOptions, remove_file};
use std::io::{Seek, SeekFrom};
use rand::Rng;  // rand crate for generating random data

fn main() -> io::Result<()> {

    let args: Vec<String> = env::args().collect();
    dbg!(&args);
    let current_dir = env::current_dir().expect("Failed to get current directory");
    //println!("Current directory: {:?}", current_dir);
    /*
    arg1 - function (help, encrypt, decrypt, delete)
    arg2 - file
    arg3 - key - must be 32 bytes
    */

    if args.len() == 1 {
        // while true session with authentication 
        // - create authentication database

    }

    if args.len() == 2 && args[1] == "help" {
        println!("To use this software, use secure.exe <function> <file_path> <key>");
        println!("Key size must be 32 bytes");
        println!("If key is not entered, it will be generated randomly and given to you as a plaintext during encryption.");
        println!("Key must be entered during decryption!");
        println!("If user is authenticated then key will be tied to authentication, unless specified differently");
        println!("functions: help, encrypt, decrypt, delete, encrypt-delete");
        println!("help - Provides this same text wall.");
        println!("encrypt - Encrypts the file, requires file path, key is optional");
        println!("decrypt - Decrypts the file, requres file path, key is mandatory");
        println!("delete - Deletes file securely");
        println!("encrypt-delete - Encrypts the file and then deletes the initial file securely, requires file path, key is optional");
    }

    if args.len() > 1 && args[1] == "encrypt" {
        if args.len() == 3 { // without key, generate random key secure.exe encrypt file ...
            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&args[2]);

            let key = generate_random_aes_key();
            println!("{:?}", hex::encode(key));
            file_encryption(file_path, key)?;
        }
        if args.len() == 4 { // with key, take user input as key, secure.exe encrypt file key

            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&args[2]);
            
            // make a random 32 bit long byte array 
            let mut byte_array = [0u8; 32];
            let input_bytes = validate_aes_key(&args[3]);

            // Step 2: Copy the first 32 bytes (or pad with 0s if shorter)
            match input_bytes {
                Some(valid_key) => {
                    // Copy the validated key into `byte_array`
                    byte_array.copy_from_slice(&valid_key);
                    println!("AES Key: {:?}", byte_array);
                }
                None => {
                    // if invalid input, promt again.
                }
            }

            let key: GenericArray<u8, U32> = GenericArray::from(byte_array);
            println!("{:?}", hex::encode(key));
            file_encryption(file_path, key)?
        }
    }

    if args.len() > 1 && args[1] == "decrypt" {
        if args.len() == 4 { // with key, take user input as key, secure.exe decrypt file key
            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&args[2]);
            
            let mut byte_array = [0u8; 32];
            let input_bytes = validate_aes_key(&args[3]);

            // Step 2: Copy the first 32 bytes (or pad with 0s if shorter)
            match input_bytes {
                Some(valid_key) => {
                    // Copy the validated key into `byte_array`
                    byte_array.copy_from_slice(&valid_key);
                    println!("AES Key: {:?}", byte_array);
                }
                None => {
                    // if invalid input, promt again.
                }
            }
            let key: GenericArray<u8, U32> = GenericArray::from(byte_array);
            file_decryption(file_path, key)?;
        } else {
            // figure something out
        }
    }

    if args.len() > 1 && args[1] == "delete" {
        if args.len() > 2 {
            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&args[2]);
            
            file_deletion(file_path)?;
        }
    }

    if args.len() > 1 && args[1] == "encrypt-delete" {
        if args.len() == 3 { // without key, generate random key secure.exe encrypt file ...
            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&args[2]);

            let key = generate_random_aes_key();
            println!("{:?}", hex::encode(key));
            file_encryption(file_path, key)?;
            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&args[2]);
            //println!("File path: {:?}",file_path);
            file_deletion(file_path)?;
        }
        if args.len() == 4 { // with key, take user input as key, secure.exe encrypt file key
            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&args[2]);
            // make a random 32 bit long byte array 
            let mut byte_array = [0u8; 32];
            let input_bytes = validate_aes_key(&args[3]);

            // Step 2: Copy the first 32 bytes (or pad with 0s if shorter)
            match input_bytes {
                Some(valid_key) => {
                    // Copy the validated key into `byte_array`
                    byte_array.copy_from_slice(&valid_key);
                    println!("AES Key: {:?}", byte_array);
                }
                None => {
                    // if invalid input, promt again.
                }
            }

            let key: GenericArray<u8, U32> = GenericArray::from(byte_array);
            file_encryption(file_path.clone(), key)?;
            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&args[2]);
            //println!("File path: {:?}",file_path);
            file_deletion(file_path)?;
            println!("AES Key: {:?}", hex::encode(key));
        }
    }

    Ok(())
}
    
    
    // ENCRYPTION/DECRYPTION --------------------------------
    /*
    
    1. Implement AES for Encryption +
    2. Implement AES for Decryption +
    3. Memory in key for guest user, key saved? for authenticated user
    4. Secure Original File Deletion + 
    
- Library 
*/
fn file_encryption(file_path: PathBuf, key: GenericArray<u8, U32>) -> io::Result<()> {

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
    
    // create new directory
    let new_directory_name = "encrypted";
    fs::create_dir_all(new_directory_name)?;
    let new_file_path = Path::new(new_directory_name).join(new_file_name);
    
    // create output file
    let mut file = File::create(&new_file_path)?;
    file.write_all(&ciphertext)?;
    drop(file_path);
    drop(file);
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

fn file_deletion(file_path: PathBuf) -> io::Result<()> {
    // Step 1: Open file in write mode
    let mut file = OpenOptions::new().write(true).open(file_path.clone())?;
    
    // Step 2: Get the file size
    let file_size = file.metadata()?.len();

    // Step 3: Overwrite file multiple times with random data
    let mut rng = rand::thread_rng();
    for _ in 0..10 {
        file.seek(SeekFrom::Start(0))?;
        let random_data: Vec<u8> = (0..file_size).map(|_| rng.gen()).collect();
        file.write_all(&random_data)?;
        file.flush()?;  // Ensure data is written to disk
    }

    // Step 4: Delete the file
    drop(file);  // Close file handle
    remove_file(file_path)?;

    Ok(())
}

fn validate_aes_key(input: &str) -> Option<GenericArray<u8, U32>> {
    // Step 1: Check if input is exactly 64 characters (32 bytes in hex)
    if input.len() != 64 {
        eprintln!("Error: AES key must be exactly 64 hexadecimal characters.");
        return None;
    }

    // Step 2: Attempt to parse as a 32-byte array
    match <[u8; 32]>::from_hex(input) {
        Ok(bytes) => Some(GenericArray::from(bytes)),
        Err(_) => {
            eprintln!("Error: Input contains invalid hexadecimal characters.");
            None
        }
    }
}

fn generate_random_aes_key() -> GenericArray<u8, U32> {
    let mut rng = rand::thread_rng();
    let mut key_bytes = [0u8; 32];
    rng.fill(&mut key_bytes); // Fill the array with random bytes
    GenericArray::from(key_bytes) // Convert to GenericArray
}

fn register(username: &str, password: &str, password_again: &str ) {

}

fn login(username: &str, password &str) {

}

fn change_password(username: &str, password: &str, new_password: &str) {

}

fn create_auth_db() -> io::Result<()> {

    Ok(())
}

fn read_auth_db() {

}

fn write_auth_db() -> io::Result<()> {

    Ok(())
}

