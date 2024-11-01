use aes::cipher::{
    generic_array::GenericArray
};
use std::env;
use std::path::PathBuf;
use std::io::{self, Write};
//use block_padding::Pkcs7;
//use aes::cipher;
use typenum::U32;
use hex;
use hex::FromHex;
use std::fs::{OpenOptions, remove_file};
use std::io::{Seek, SeekFrom};
use rand::Rng;  // rand crate for generating random data
use redb::{Database, ReadableTable, TableDefinition};
use std::borrow::Borrow;
use argon2::{self, Config};

mod encryption;
mod db_entry;
mod my_key;

const TABLE: TableDefinition<&str, &str> = TableDefinition::new("accounts");

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let args: Vec<String> = env::args().collect();
    //dbg!(&args);
    let current_dir = env::current_dir().expect("Failed to get current directory");
    
    //println!("Current directory: {:?}", current_dir);
    /*
    arg1 - function (help, encrypt, decrypt, delete)
    arg2 - file
    arg3 - key - must be 32 bytes
    
    */

    let salt = b"858dc1dfe1f";
    let config = Config::default();
    //let hash = argon2::hash_encoded(password, salt, &config).unwrap();
    //assert!(matches);
    //println!("{}",matches);
    
    if args.len() == 1 {
        let db = Database::open(db_var())?;
        let mut while_flag = true;
        let mut account_name: Option<String> = None; // Use Option<String> to store the username
        
        while while_flag {
            println!("Enter 'q' to quit or write 'help' to see other commands:");
            
            let mut input = String::new();
            io::stdin()
            .read_line(&mut input)
            .expect("Failed to read input");
        
        let command = input.trim();
        
        if command == "q" {
            while_flag = false;

        } else if command == "all_entries" {
            read_all_entries(&db)?;

        } else if command == "gen_key" {
            let generated_key = generate_random_aes_key();
            println!("{:?}", hex::encode(generated_key));

        } else if command == "set_db_key" {
            println!("Please enter valid AES key that you want to encrypt database with");
            let mut db_key = String::new();
            io::stdin()
            .read_line(&mut db_key)
            .expect("Failed to read input");
            println!("{:?}", db_key.as_bytes().to_vec());

        } else if command == "help" {
            help_menu();
        } else if command == "decrypt-file" {
        } else if command == "encrypt-file-rng-key" {
            if account_name.is_none() {
                println!("Please authenticate first");
            } else {
                
                let mut file_path = PathBuf::from(&current_dir);
                
                let key = generate_random_aes_key();
                
                println!("Enter file you want to encrypt:");
                let mut file_name = String::new();
                io::stdin()
                .read_line(&mut file_name)
                .expect("Failed to read input");
                
                file_path.push(&file_name.trim());
                //println!("file path: {}", &file_path.display());
                println!("{:?}", hex::encode(&key));
                encryption::file_encryption(file_path, key)?;
            }

        } else if command == "encrypt-file" {    
        } else if command == "encrypt" {
            if account_name.is_none() {
                println!("Please authenticate first.");
            } else {
            println!("Enter phrase you want to encrypt:");
            let mut plaintext = String::new();
            io::stdin()
            .read_line(&mut plaintext)
            .expect("Failed to read input");
                println!("{:?}",db_entry::encrypt_db_entry(plaintext));
            }
        } else if command == "decrypt" {
            if account_name.is_none() {
                println!("Please authenticate first.");
            } else {

                println!("Enter ciphertext you want to decrypt:");
                let mut ciphertext = String::new();
                io::stdin()
                .read_line(&mut ciphertext)
                .expect("Failed to read input");
            println!("{}",db_entry::decrypt_db_entry(ciphertext));
        }
        } else if command == "login" {
            if account_name.is_none() {
                
                println!("Enter username you want for your account:");
                let mut username = String::new();
                io::stdin()
                .read_line(&mut username)
                .expect("Failed to read input");
            
                println!("Enter password you want for your account:");
                let mut password = String::new();
                io::stdin()
                .read_line(&mut password)
                .expect("Failed to read input");

            let pre_account_name = Some(username.trim().to_string()); // Store trimmed username as a String
            let pre_account_password = Some(password.trim().to_string()); // Store trimmed password as a String

            let hash_username = argon2::hash_encoded(pre_account_name.clone().unwrap().as_bytes(), salt, &config).unwrap();

            let encrypted_username = db_entry::encrypt_db_entry(hash_username.clone());

            match get_value_by_key(&db, &encrypted_username)? {
                Some(value) => 
                if argon2::verify_encoded(&db_entry::decrypt_db_entry(value.to_string()).to_string(), pre_account_password.clone().unwrap().as_bytes()).unwrap_or(false) {
                        account_name = Some(username.trim().to_string()); // Store trimmed username as a String
                        println!("user {} has authenticated!", account_name.clone().unwrap());
                    } else {
                        //TEST:
                        //println!("username: {}", encrypted_username);
                        //println!("&value: {}", &value);
                        //println!("pre_account_password: {:?}", pre_account_password.unwrap().as_bytes());

                        // PROD:
                        println!("Invalid Credentials.");
                    },
                None => println!("Invalid Credentials."),
            }
        

            } else {
                println!("Already authenticated");
            }
        } else if command == "register" {
            if account_name.is_none() {
                println!("Enter username you want for your account:");
                let mut username = String::new();
                io::stdin()
                .read_line(&mut username)
                .expect("Failed to read input");
            
                println!("Enter password you want for your account:");
                let mut password = String::new();
                io::stdin()
                .read_line(&mut password)
                .expect("Failed to read input");

                println!("Enter password again:");
                let mut password_again = String::new();
                io::stdin()
                .read_line(&mut password_again)
                .expect("Failed to read input");          
            
                if password.trim() == password_again.trim() { // Check if passwords match
                    account_name = Some(username.trim().to_string()); // Store trimmed username as a String
                    let account_password = Some(password.trim().to_string()); // Store trimmed password as a String

                    println!("Your username is: {} and your password has been set.", account_name.as_ref().unwrap());
                    let hash_password = argon2::hash_encoded(account_password.clone().unwrap().as_bytes(), salt, &config).unwrap();
                    let hash_username = argon2::hash_encoded(account_name.clone().unwrap().as_bytes(), salt, &config).unwrap();

                    let write_txn = db.begin_write()?;
                    {
                        let mut table = write_txn.open_table(TABLE)?;
                        let encrypted_username = db_entry::encrypt_db_entry(hash_username.clone());
                        let encrypted_password = db_entry::encrypt_db_entry(hash_password.clone());
                        table.insert(encrypted_username.as_str(), encrypted_password.as_str())?;
                    }
                write_txn.commit()?;
                } else {
                    println!("Passwords do not match. Please try again.");
                }
            } else {
                println!("Account name is already set to: {}", account_name.as_ref().unwrap());
            }
        }
        }
    } 

    if args.len() == 2 && args[1] == "help" {
        help_menu();
    }

    if args.len() > 1 && args[1] == "encrypt" {
        if args.len() == 3 { // without key, generate random key secure.exe encrypt file ...
            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&args[2]);

            let key = generate_random_aes_key();
            println!("{:?}", hex::encode(key));
            encryption::file_encryption(file_path, key)?;
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
            encryption::file_encryption(file_path, key)?
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
            encryption::file_decryption(file_path, key)?;
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
            encryption::file_encryption(file_path, key)?;
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
            encryption::file_encryption(file_path.clone(), key)?;
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

fn help_menu() {

    println!("To use this software, use secure.exe <function> <file_path> <key>
    Key size must be 32 bytes
    If key is not entered, it will be generated randomly and given to you as a plaintext during encryption.
    Key must be entered during decryption!
    If user is authenticated then key will be tied to authentication, unless specified differently
    functions: help, encrypt, decrypt, delete, encrypt-delete
    help - Provides this same text wall.
    encrypt - Encrypts the file, requires file path, key is optional
    decrypt - Decrypts the file, requres file path, key is mandatory
    delete - Deletes file securely
    encrypt-delete - Encrypts the file and then deletes the initial file securely, requires file path, key is optional");
    
}

fn db_var() -> PathBuf {
    PathBuf::from("secure_database.redb")
}

fn read_all_entries(db: &Database) -> Result<(), Box<dyn std::error::Error>> {
    // Start a read transaction
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(TABLE)?;

    // Iterate over all entries in the table
    for entry in table.iter()? {
        let (key, value) = entry?;
        let key_str = key.borrow(); // This should return a &str
        let value_str = value.borrow(); // This should return a &str

        // Print the key and value
        println!("Key: {}, Value: {}", key_str.value(), value_str.value());

    }

    Ok(())
}

fn get_value_by_key(db: &Database, key: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // Open the database file

    // Start a read transaction
    let read_txn = db.begin_read()?;

    // Open the table
    let table = read_txn.open_table(TABLE)?;

    //println!("Key in function is: {}", key);

    // Get the value by key
    match table.get(key)? {
        Some(value) => {
            //println!("value is: {}", value.value().to_string());
            Ok(Some(value.value().to_string()))
        },
        None => Ok(None), // Key does not exist
    }
}