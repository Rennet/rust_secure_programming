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
    arg3 - key
    */

    if args.len() > 1 && args[1] == "help" {
        println!("To use this software, use secure.exe <function> <file_path> <key>")
    }

    if args.len() > 1 && args[1] == "encrypt" {
        if args.len() > 2 {
            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&args[2]);

            let key = GenericArray::from([0u8; 32]);
            file_encryption(file_path, key)?;
        }
    }




    // ---- file read -----
    // file_path.push(&args[2]);
    
    //println!("In file {}", file_path.display());
    /*
    let contents = fs::read_to_string(file_path)
    .expect("Should have been able to read the file");
let mut plaintext = contents.clone().into_bytes();

// Padding
let padding_length = 16 - (plaintext.len() % 16);
plaintext.extend(vec![padding_length as u8; padding_length]);



println!("With text:\n{contents}");
*/

// ---- file read -----

// ---- file write ----
//let mut file = File::create("output.txt")?;
//let mut key_file = File::create("key.txt")?;

// Write a string to the file
// file.write_all(b"Hello, world!")?;

// Optional: write additional data
    // file.write_all(b"\nThis is a new line.")?;

    // ------------------------- 


    //let key = GenericArray::from([u8; 32]);
    //let mut block = GenericArray::from([42u8; 16]);
    //println!("key: {}", hex::encode(key));
    //println!("block: {}", hex::encode(block));
    
/* 
    // Initialize cipher
    let cipher = Aes256::new(&key);
    
    //let block_copy = block.clone();
    let mut blocks: Vec<GenericArray<u8, aes::cipher::consts::U16>> = plaintext
    .chunks_exact(16)
    .map(|chunk| GenericArray::clone_from_slice(chunk))
    .collect();

for block in &mut blocks {
    cipher.encrypt_block(block);
}

// Convert encrypted blocks back to a byte array
let ciphertext: Vec<u8> = blocks.iter()
.flat_map(|block| block.as_slice())
.cloned().collect();

file.write_all(&ciphertext)?;
// Encrypt block in-place

 */
    
    
    
    
    //cipher.encrypt_block(&mut block);
    //println!("encrypted: {}", hex::encode(block));

    // And decrypt it back
    //cipher.decrypt_block(&mut block);
    //assert_eq!(block, block_copy);
    //println!("decrypted: {}", hex::encode(block));
    
    // Implementation supports parallel block processing. Number of blocks
    // processed in parallel depends in general on hardware capabilities.
    // This is achieved by instruction-level parallelism (ILP) on a single
    // CPU core, which is differen from multi-threaded parallelism.
    //let mut blocks = [block; 32];
    //println!("blocks (before encryption): {}", blocks.iter().map(hex::encode).collect::<Vec<_>>().join(", "));
    //cipher.encrypt_blocks(&mut blocks);
    //println!("blocks (after encryption): {}", blocks.iter().map(hex::encode).collect::<Vec<_>>().join(", "));
    /*
    for block in blocks.iter_mut() {
        cipher.decrypt_block(block);
        assert_eq!(block, &block_copy);
    }
    
    // `decrypt_blocks` also supports parallel block processing.
    cipher.decrypt_blocks(&mut blocks);
    
    for block in blocks.iter_mut() {
        cipher.encrypt_block(block);
        assert_eq!(block, &block_copy);
    }
    */

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
/*

fn file_decryption() {
    
}

fn file_deletion() {

}
*/

//-----------------------------------

//Security -------------------------------------
/*

fn sanitization() {

}

fn max_length() {

}

*/

// Authentication

/*

*/

// Input Validation

/*

*/


// Logging and Error Handling

/*

*/