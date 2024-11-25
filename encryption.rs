use aes::Aes256;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray
};
use std::fs;
use std::path::PathBuf;
use std::fs::File;
use std::io::{self, Write};
use typenum::U32;

pub fn file_encryption(file_path: PathBuf, key: GenericArray<u8, U32>) -> io::Result<()> {

    // file name
    //println!("{}",&file_path.display());
    let file_name = &file_path.file_stem().unwrap();
    //println!("{:?}",&file_name);

    let new_file_name = format!("{}{}", file_name.to_str().unwrap(), ".encrypted.rt");
    //println!("{}",&new_file_name);

    let contents = fs::read(file_path.clone()).expect("Should have been able to read the file");
    //println!("{:?}",&contents);
    let mut plaintext = contents.clone();
    
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
    //println!("new_file_stem: {}",new_file_stem);

    // Create the new file name with ".decrypted.txt" extension
    let new_file_name = format!("{}", new_file_stem,);
    //println!("new_file_name: {}",new_file_name);
    
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
    drop(file_path);
    drop(file);

    Ok(())
}

pub fn text_encryption(plaintext: String, key: GenericArray<u8, U32>) -> String {

    let contents = plaintext.into_bytes();
    let mut plaintext = contents.clone();
    
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

    // string output
    hex::encode(ciphertext).to_string()
}

pub fn text_decryption(ciphertext: String, key: GenericArray<u8, U32>) -> String {
    // Read the encrypted file
    let encrypted_data = hex::decode(ciphertext.trim()).expect("Failed to decode hex text");
    
    // cipher
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

    //String result
    String::from_utf8(decrypted_data).expect("Decrypted data is not valid UTF-8").trim().to_string()
}


#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::generic_array::GenericArray;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::fs::OpenOptions;
    use std::io::SeekFrom;
    use std::fs::remove_file;
    use rand::Rng;
    use std::io::Seek;

    
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

    #[test]
    fn test_file_encryption_and_decryption() -> io::Result<()> {
        // Generate test key
        let key = GenericArray::from_slice(&[0u8; 32]); // Replace with a more realistic key for production

        // Create a temporary file for testing
        let test_file_path = PathBuf::from("test_file.txt");
        let test_data = b"Hello, secure world!";
        fs::write(&test_file_path, test_data)?;

        // Encrypt the file
        file_encryption(test_file_path.clone(), key.clone())?;
        println!("1");

        // Ensure encrypted file exists
        let encrypted_file_path = PathBuf::from("test_file.encrypted.rt");
        assert!(
            encrypted_file_path.exists(),
            "Encrypted file not found: {}",
            encrypted_file_path.display()
        );

        println!("2");
        // Decrypt the file
        file_decryption(encrypted_file_path.clone(), key.clone())?;

        println!("3");
        // Ensure decrypted file exists and matches original content
        let decrypted_file_path = PathBuf::from("test_file.txt");
        assert!(
            decrypted_file_path.exists(),
            "Decrypted file not found: {}",
            decrypted_file_path.display()
        );
        println!("4");
        let decrypted_data = fs::read(&decrypted_file_path)?;
        assert_eq!(
            decrypted_data, test_data,
            "Decrypted data does not match original content"
        );
        println!("5");

        // Cleanup
        fs::remove_file(encrypted_file_path)?;
        fs::remove_file(decrypted_file_path)?;

        Ok(())
    }

    #[test]
    fn test_text_encryption_and_decryption() {
        // Generate test key
        let key = GenericArray::from_slice(&[0u8; 32]); // Replace with a more realistic key for production

        // Test data
        let plaintext = "Hello, secure world!".to_string();

        // Encrypt the text
        let ciphertext = text_encryption(plaintext.clone(), key.clone());

        // Decrypt the text
        let decrypted_text = text_decryption(ciphertext, key.clone());

        // Verify the result
        assert_eq!(plaintext, decrypted_text);
    }

    #[test]
    fn test_file_deletion_success() -> io::Result<()> {
        // Create a temporary file for testing
        let test_file_path = PathBuf::from("test_file_to_delete.txt");
        fs::write(&test_file_path, b"Temporary file content")?;

        // Ensure the file exists
        assert!(
            test_file_path.exists(),
            "Test file not found: {}",
            test_file_path.display()
        );

        // Call file_deletion
        file_deletion(test_file_path.clone())?;

        // Ensure the file has been deleted
        assert!(
            !test_file_path.exists(),
            "File was not deleted: {}",
            test_file_path.display()
        );

        Ok(())
    }

    #[test]
    fn test_file_deletion_empty_file() -> io::Result<()> {
        // Create an empty file
        let test_file_path = PathBuf::from("empty_file_to_delete.txt");
        File::create(&test_file_path)?;

        // Ensure the file exists
        assert!(
            test_file_path.exists(),
            "Empty test file not found: {}",
            test_file_path.display()
        );

        // Call file_deletion
        file_deletion(test_file_path.clone())?;

        // Ensure the file has been deleted
        assert!(
            !test_file_path.exists(),
            "Empty file was not deleted: {}",
            test_file_path.display()
        );

        Ok(())
    }
}