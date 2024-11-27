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
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn file_encryption(file_path: PathBuf, key: GenericArray<u8, U32>) -> io::Result<()> {

    //Check if file exists, if not put back to the menu
    if !file_path.exists() {
        println!("Error: File does not exist. Returning to the menu...");
        return Ok(()); // Exit gracefully
    }

    // file name
    let file_name = file_path
        .file_stem()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid file path"))?;
    let new_file_name = format!("{}{}", file_name.to_string_lossy(), ".encrypted.rt");

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
    println!("Storing file: {:?}", &file_path);

    // Generate HMAC
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(&key)
        .expect("HMAC can take key of any size");
    hmac.update(&ciphertext); // Add ciphertext to HMAC computation
    let hmac_result = hmac.finalize().into_bytes(); // Get HMAC as bytes

    // Combine ciphertext and HMAC
    let mut output_data = ciphertext;
    output_data.extend(hmac_result);

    // create output file
    let mut file = File::create(&new_file_name)?;
    file.write_all(&output_data)?;
    drop(file_path);
    drop(file);

    println!("AES Key: {:?}", hex::encode(&key).trim());
    println!("HMAC: {:?}", hex::encode(hmac_result).trim());
    println!("Stored File name: {}", &new_file_name);
    Ok(())
}

pub fn file_decryption(file_path: PathBuf, key: GenericArray<u8, U32>) -> io::Result<()> {
    // File name for decrypted output
    let file_stem = file_path
        .file_stem()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid file path"))?;
    let file_stem_str = file_stem.to_string_lossy();

    // Remove the ".encrypted.rt" from the stem if it exists
    let new_file_stem = file_stem_str.trim_end_matches(".encrypted");

    // Create the new file name with ".decrypted.txt" extension
    let new_file_name = format!("{}", new_file_stem,);
    //println!("new_file_name: {}",new_file_name);

    // Read the encrypted file
    let encrypted_data = fs::read(&file_path)?;

    if encrypted_data.len() < 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "File too small to contain valid HMAC"));
    }
    let (ciphertext, received_hmac) = encrypted_data.split_at(encrypted_data.len() - 32);

    let mut hmac = <HmacSha256 as Mac>::new_from_slice(&key)
        .expect("HMAC can take key of any size");
    hmac.update(ciphertext);

    hmac.verify_slice(received_hmac)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HMAC verification failed"))?;

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
    if  usize::from(padding_length) > decrypted_data.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid padding length"));
    }
    decrypted_data.truncate(decrypted_data.len() - padding_length as usize);

    // Create output file
    let mut file = File::create(&new_file_name)?;
    file.write_all(&decrypted_data)?;

    println!("Decryption successful.");
    println!("Decrypted file name: {}", new_file_name);
    
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

pub fn file_store(file_path: PathBuf, key: GenericArray<u8, U32>, destination: &str) -> io::Result<()> {
    // Check if file exists, if not return to the menu
    const ALLOWED_ROOT: &str = "C:\\Secureprogramming";

    // Check if the file exists
    if !file_path.exists() {
        println!("Error: File does not exist. Returning to the menu...");
        return Ok(()); // Exit gracefully
    }

    // Resolve the canonical path of the destination
    let destination_path = fs::canonicalize(destination).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "Invalid destination path")
    })?;

    // Check if the destination starts with the allowed root directory
    let allowed_root = fs::canonicalize(ALLOWED_ROOT).expect("Allowed root directory should exist");
    if !destination_path.starts_with(&allowed_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Files can only be stored in C:\\Secureprogramming\\",
        ));
    }

    // Extract the file name
    let file_name = file_path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "Invalid file path")
    })?;

    // Combine destination and file name
    let new_file_name = format!("{}\\{}", destination.trim_end_matches('\\'), file_name.to_string_lossy());
    println!("Encrypting file: {:?}", file_path);
    // println!("Destination file: {}", new_file_name);

    // Read the file contents
    let mut plaintext = fs::read(&file_path)?;

    // Padding
    let padding_length = 16 - (plaintext.len() % 16);
    plaintext.extend(vec![padding_length as u8; padding_length]);

    // Cipher setup
    let cipher = Aes256::new(&key);
    let mut blocks: Vec<GenericArray<u8, aes::cipher::consts::U16>> = plaintext
        .chunks_exact(16)
        .map(|chunk| GenericArray::clone_from_slice(chunk))
        .collect();

    // Encrypt blocks
    for block in &mut blocks {
        cipher.encrypt_block(block);
    }

    // Convert encrypted blocks to byte array
    let ciphertext: Vec<u8> = blocks.iter()
        .flat_map(|block| block.as_slice())
        .cloned()
        .collect();

    // Write encrypted contents to the new file
    let mut file = File::create(&new_file_name)?;
    file.write_all(&ciphertext)?;

    println!("AES Key: {:?}", hex::encode(&key).trim());
    // println!("Encrypted File name: {}", new_file_name);
    Ok(())
}

pub fn file_retrieve(file_path: PathBuf, key: GenericArray<u8, U32>) -> io::Result<()> {
    //Check if file exists, if not put back to the menu
    if !file_path.exists() {
        println!("Error: File does not exist. Returning to the menu...");
        return Ok(()); // Exit gracefully
    }

    // File name for decrypted output
    let file_stem = file_path.file_stem().unwrap();
    let file_stem_str = file_stem.to_str().unwrap();
    println!("file_stem_str: {}",file_stem_str);

    // Remove the ".encrypted.rt" from the stem if it exists
    let new_file_name = file_stem_str.trim_end_matches(".encrypted.rt");

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
            let random_data: Vec<u8> = (0..file_size).map(|_| rng.gen::<u8>()).collect();
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

        // Ensure encrypted file exists
        let encrypted_file_path = PathBuf::from("test_file.encrypted.rt");
        assert!(
            encrypted_file_path.exists(),
            "Encrypted file not found: {}",
            encrypted_file_path.display()
        );

        // Decrypt the file
        file_decryption(encrypted_file_path.clone(), key.clone())?;

        // Ensure decrypted file exists and matches original content
        let decrypted_file_path = PathBuf::from("test_file.txt");
        assert!(
            decrypted_file_path.exists(),
            "Decrypted file not found: {}",
            decrypted_file_path.display()
        );

        let decrypted_data = fs::read(&decrypted_file_path)?;
        assert_eq!(
            decrypted_data, test_data,
            "Decrypted data does not match original content"
        );

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

    #[test]
fn test_decryption_with_wrong_key() -> io::Result<()> {
    let key = GenericArray::from_slice(&[0u8; 32]);
    let wrong_key = GenericArray::from_slice(&[1u8; 32]);

    let test_file_path = PathBuf::from("wrong_key_test.txt");
    fs::write(&test_file_path, b"Test content")?;

    file_encryption(test_file_path.clone(), key.clone())?;

    let encrypted_file_path = PathBuf::from("wrong_key_test.encrypted.rt");
    assert!(
        encrypted_file_path.exists(),
        "Encrypted file not found"
    );

    let result = file_decryption(encrypted_file_path.clone(), wrong_key.clone());
    assert!(
        result.is_err(),
        "Decryption with wrong key should fail"
    );

    fs::remove_file(encrypted_file_path)?;
    fs::remove_file(test_file_path)?;
    Ok(())
}

#[test]
fn test_tampered_data_detection() -> io::Result<()> {
    let key = GenericArray::from_slice(&[0u8; 32]);

    let test_file_path = PathBuf::from("tampered_test.txt");
    fs::write(&test_file_path, b"Original content")?;

    file_encryption(test_file_path.clone(), key.clone())?;

    let encrypted_file_path = PathBuf::from("tampered_test.encrypted.rt");
    assert!(
        encrypted_file_path.exists(),
        "Encrypted file not found"
    );

    let mut tampered_data = fs::read(&encrypted_file_path)?;
    tampered_data[0] ^= 0xFF; // Modify a byte to simulate tampering
    fs::write(&encrypted_file_path, tampered_data)?;

    let result = file_decryption(encrypted_file_path.clone(), key.clone());
    assert!(
        result.is_err(),
        "Decryption of tampered data should fail"
    );

    fs::remove_file(encrypted_file_path)?;
    fs::remove_file(test_file_path)?;
    Ok(())
}

#[test]
fn test_store_file_outside_allowed_path() -> io::Result<()> {
    let key = GenericArray::from_slice(&[0u8; 32]);

    let test_file_path = PathBuf::from("test_file_outside.txt");
    fs::write(&test_file_path, b"Content")?;

    let result = file_store(test_file_path.clone(), key.clone(), "C:\\UnauthorizedPath\\");
    assert!(
        result.is_err(),
        "Storing file outside allowed root should fail"
    );

    fs::remove_file(test_file_path)?;
    Ok(())
}

#[test]
fn test_invalid_padding_handling() -> io::Result<()> {
    let key = GenericArray::from_slice(&[0u8; 32]);

    let mut invalid_data = vec![0u8; 48]; // Incorrect padding
    invalid_data[47] = 50; // Invalid padding value
    let test_file_path = PathBuf::from("invalid_padding_test.encrypted.rt");
    fs::write(&test_file_path, &invalid_data)?;

    let result = file_decryption(test_file_path.clone(), key.clone());
    assert!(
        result.is_err(),
        "Decryption of data with invalid padding should fail"
    );

    fs::remove_file(test_file_path)?;
    Ok(())
}
}