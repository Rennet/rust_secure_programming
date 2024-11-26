use aes::cipher::{generic_array::GenericArray};
use encryption::{file_retrieve, file_store};
use std::env;
use std::path::PathBuf;
use std::io::{self, Write};
use typenum::U32;
use hex;
use hex::FromHex;
use std::fs::{OpenOptions, remove_file};
use std::fs;
use std::io::{Seek, SeekFrom};
use std::fs::File;
use std::path::Path;
use std::thread;
use std::time::Duration;
use std::process;
use std::ptr;
use rand::Rng;  // rand crate for generating random data
use argon2::{self, Config};
use rpassword::read_password;
use google_authenticator::{GoogleAuthenticator, ErrorCorrectionLevel, GA_AUTH, verify_code};
use secrecy::{SecretBox, ExposeSecret};
use open;
use rand::distributions::Alphanumeric;
use base32::encode;
use base32::Alphabet::Rfc4648;
use dialoguer::{theme::ColorfulTheme, Select};
use wincredentials::*;
mod encryption;
use winapi::um::winbase::{RegisterEventSourceW, ReportEventW, DeregisterEventSource};
use winapi::um::winnt::EVENTLOG_ERROR_TYPE;
use winapi::um::winnt::EVENTLOG_INFORMATION_TYPE;
use widestring::U16CString;
use std::panic;
use std::fs::create_dir_all;

const STORAGE_FILES_DIR: &str = "C:\\secureprogramming\\";

fn main() -> Result<(), Box<dyn std::error::Error>> {

        env_logger::init();

        // Set up the panic hook
        panic::set_hook(Box::new(|info| {
            let log_message = format!("ERROR: {info}");
            log_to_event_viewer(&log_message, EVENTLOG_ERROR_TYPE);
        }));

        // Log an informational event
        log_to_event_viewer("Application started successfully", EVENTLOG_INFORMATION_TYPE);

        // Create directory on initialization if does not exist.
        create_dir_all(STORAGE_FILES_DIR)?;

        // Define DB
        let username_db = "secureprogramming-user-test2";
        let salt = b"858dc1dfe1f";
        let config = Config::default();

        let secret = SecretBox::new(Box::new("YU38IWO1K3B9W0DIWBID3LDEVFXZGG54".to_string()));
        let base32_secret = SecretBox::new(Box::new(encode(Rfc4648 { padding: true }, secret.expose_secret().as_bytes())));
        let auth = GoogleAuthenticator::new();

        // Check if database exists, if not, then prompt to registration.
        match read_credential(username_db) {
            Ok(credential) => { //credentials exist
                println!("Please authenticate to use this software.");
                println!("Enter username:");
                let mut username = String::new();
                io::stdin()
                .read_line(&mut username)
                .expect("Failed to read input");
            let username = username.trim();

            println!("Enter password:");
            let password = read_password().expect("Failed to read password");
            let password = password.trim();

            // Verifying credentials
            if argon2::verify_encoded(&credential.username, username.as_bytes()).unwrap() {
                if argon2::verify_encoded(&credential.secret, password.as_bytes()).unwrap() {
                    println!("Enter MFA TOTP:");
                    let mut code = String::new();
                    io::stdin()
                    .read_line(&mut code)
                    .expect("Failed to read input");
                let mfa_code = code.trim();

                if verify_code!(&base32_secret.expose_secret(), &mfa_code, 1, 0) {
                    println!("Authentication successful");
                    // Log an informational event - User authenticated
                    let log_message = format!("{username} Authenticated successfully.");
                    log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
                } else {
                    println!("Authentication failed.");
                    let log_message = format!("{username} Failed to authenticate - incorrect MFA.");
                    log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
                    quit();
                }
                // Successful authentication
            } else {
                println!("Authentication failed.");
                let log_message = format!("{username} Failed to authenticate - Wrong credentials.");
                log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
                quit();
            }
        } else {
            println!("Authentication failed.");
            let log_message = format!("{username} Failed to authenticate - Wrong credentials.");
            log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
            quit();
        }
    }
    Err(error) => { // No credentials exist
        println!("Error: {error}");
        println!("No credential found. Prompting for registration...");
        println!("Enter username you want for your account:");
        let mut username = String::new();
        io::stdin()
        .read_line(&mut username)
        .expect("Failed to read input");

        println!("Enter password you want for your account:");
        let password = read_password().expect("Failed to read password");
        let password = password.trim();

        println!("Enter password again:");
        let password_again = read_password().expect("Failed to read password");
        let password_again = password_again.trim();

        if password.trim() == password_again.trim(){
            let account_name = Some(username.trim().to_string()); // Store trimmed username as a String
            let account_password = Some(password.trim().to_string()); // Store trimmed password as a String

            println!("Your username is: {} and your password has been set.", account_name.as_ref().unwrap());
            let log_message = format!("{username} successfully registered.");
            log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
            let hash_password = argon2::hash_encoded(account_password.clone().unwrap().as_bytes(), salt, &config).unwrap();
            let hash_username = argon2::hash_encoded(account_name.clone().unwrap().as_bytes(), salt, &config).unwrap();

            let _ = write_credential(username_db, credential::Credential{
                username: hash_username.to_owned(),
                secret: hash_password.to_owned(),
            });

            let qr_code = auth.qr_code(base32_secret.expose_secret(), "Secure_Programming", &username, 200, 200, ErrorCorrectionLevel::High)
                .unwrap();
                // Print out the secret to verify it's correct
                println!("Secret: {}", base32_secret.expose_secret());
                println!("Generating QR code, please do not close it without scanning, there is no way to get it again.");

                let random_filename: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(20) // Specify the length of the random string
                .map(char::from)
                .collect();

                let file_name = format!("{}.svg", random_filename);

                thread::sleep(Duration::new(4, 0));
                let mut file = File::create(&file_name)?;
                file.write_all(qr_code.as_bytes())?;
                drop(file);

                open::that(&file_name)?;
                // Delete the file
                thread::sleep(Duration::new(1, 0));
                let path: PathBuf = PathBuf::from(file_name);
                file_deletion(path)?;
            }

        }
}

let current_dir = env::current_dir().expect("Failed to get current directory");

let commands = vec![
    "Generate Key",
    "Help",
    "Store",
    "Retrieve",
    "Encrypt File",
    "Decrypt File",
    "Delete File",
    "Encrypt Text",
    "Decrypt Text",
    "Change Password",
    "Quit",
    ];

    loop {
        // Display the menu and let the user select a command
        let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose a command")
        .items(&commands)
        .default(0) // Preselect the first item
        .interact()
        .expect("Failed to display menu");

    match commands[selection] {
        "Generate Key" => {
            let generated_key = generate_random_aes_key();
            println!("Generated Key: {:?}", hex::encode(generated_key));
        }
        "Help" => {
            help_menu();
        }
        "Store" => {
            println!("Do you want to automatically generate the key? If you have your own key, press any other key (y/n):");
            let mut key_choice = String::new();
            io::stdin()
            .read_line(&mut key_choice)
            .expect("Failed to read input");

            println!("Do you want to list files in the current directory? (y/n):");
            let mut list_files_choice = String::new();
            io::stdin()
            .read_line(&mut list_files_choice)
            .expect("Failed to read input");

            if list_files_choice.trim().eq_ignore_ascii_case("y") {
                list_files_in_directory(&current_dir);
            }

            println!("Type the file name, relative path or full path. (auto-completion supported. NB! Auto-completion prioritizes alphabetically and works only on current directory.):");
            let file_name = get_file_with_completion(&current_dir);

            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&file_name.trim());

            let key: GenericArray<u8, U32>;

            if key_choice.trim().eq_ignore_ascii_case("y") {
                key = generate_random_aes_key();
            } else {
                let mut byte_array = [0u8; 32];
                println!("Enter the key for the file you want to encrypt:");
                let mut entered_key = String::new();
                io::stdin()
                .read_line(&mut entered_key)
                .expect("Failed to read input");
                let input_bytes = validate_aes_key(&entered_key.trim());
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
            key = GenericArray::from(byte_array);
            }
            file_store(file_path, key, STORAGE_FILES_DIR)?;
            let log_message = format!("Authenticated user stored a file.");
            log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
        }
        "Retrieve" => {
            println!("Do you want to list files in the current storage? (y/n):");
            let mut list_files_choice = String::new();
            io::stdin()
            .read_line(&mut list_files_choice)
            .expect("Failed to read input");

            if list_files_choice.trim().eq_ignore_ascii_case("y") {
                list_files_in_directory(Path::new(STORAGE_FILES_DIR));
            }

            println!("Type the file name, relative path or full path. (auto-completion supported. NB! Auto-completion prioritizes alphabetically and works only on current directory.):");

            let file_name = get_file_with_completion(Path::new(&STORAGE_FILES_DIR));

            let mut byte_array = [0u8; 32];

            println!("Enter the key for the file you want to retrieve:");
            let mut entered_key = String::new();
            io::stdin()
            .read_line(&mut entered_key)
            .expect("Failed to read input");

            let input_bytes = validate_aes_key(&entered_key.trim());

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

            let full_file = format!("{}{}", STORAGE_FILES_DIR, file_name);
            let _ = file_retrieve(full_file.into(), key);

            let log_message = format!("Authenticated user Retrieved a file.");
            log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
        }
        "Encrypt File" => {
            println!("Do you want to automatically generate the key? If you have your own key, press any other key (y/n):");
            let mut key_choice = String::new();
            io::stdin()
            .read_line(&mut key_choice)
            .expect("Failed to read input");

            println!("Do you want to list files in the current directory? (y/n):");
            let mut list_files_choice = String::new();
            io::stdin()
            .read_line(&mut list_files_choice)
            .expect("Failed to read input");

            if list_files_choice.trim().eq_ignore_ascii_case("y") {
                list_files_in_directory(&current_dir);
            }

            println!("Type the file name, relative path or full path. (auto-completion supported. NB! Auto-completion prioritizes alphabetically and works only on current directory.):");
            let file_name = get_file_with_completion(&current_dir);

            let mut file_path = PathBuf::from(&current_dir);
            file_path.push(&file_name.trim());

            let key: GenericArray<u8, U32>;

            if key_choice.trim().eq_ignore_ascii_case("y") {
                key = generate_random_aes_key();
            } else {
                let mut byte_array = [0u8; 32];
                println!("Enter the key for the file you want to encrypt:");
                let mut entered_key = String::new();
                io::stdin()
                .read_line(&mut entered_key)
                .expect("Failed to read input");
                let input_bytes = validate_aes_key(&entered_key.trim());
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
            key = GenericArray::from(byte_array);
            }
            encryption::file_encryption(file_path, key)?;
        }
        "Decrypt File" => {
                            println!("Do you want to list files in the current directory? (y/n):");
                            let mut list_files_choice = String::new();
                            io::stdin()
                            .read_line(&mut list_files_choice)
                            .expect("Failed to read input");
                        if list_files_choice.trim().eq_ignore_ascii_case("y") {
                            list_files_in_directory(&current_dir);
                        }
                        println!("Enter file you want to decrypt or enter its relative path.:");
                        let mut file_name = String::new();
                        io::stdin()
                        .read_line(&mut file_name)
                        .expect("Failed to read input");
                    let mut file_path = PathBuf::from(&current_dir);
                    file_path.push(&file_name.trim());

                    let mut byte_array = [0u8; 32];

                    println!("Enter the key for the file you want to decrypt:");
                    let mut entered_key = String::new();
                    io::stdin()
                    .read_line(&mut entered_key)
                    .expect("Failed to read input");

                let input_bytes = validate_aes_key(&entered_key.trim());

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
                
                println!("{:?}", hex::encode(&key));
                encryption::file_decryption(file_path, key)?;
            }
        "Delete File" => {

                    println!("Do you want to list files in the current directory? (y/n):");
                    let mut list_files_choice = String::new();
                    io::stdin()
                    .read_line(&mut list_files_choice)
                    .expect("Failed to read input");

                    if list_files_choice.trim().eq_ignore_ascii_case("y") {
                        list_files_in_directory(&current_dir);
                    }

                    println!("Enter file you want to delete:");
                    let mut file_name = String::new();
                    io::stdin()
                    .read_line(&mut file_name)
                    .expect("Failed to read input");

                let mut file_path = PathBuf::from(&current_dir);
                file_path.push(&file_name.trim());

                file_deletion(file_path)?;
                }
        "Encrypt Text" => {
                        println!("Enter phrase you want to encrypt:");
                        let mut plaintext = String::new();
                        io::stdin()
                        .read_line(&mut plaintext)
                        .expect("Failed to read input");

                    println!("Enter a key, or leave empty for randomly generated one.");
                    let mut byte_array = [0u8; 32];
                    let mut entered_key = String::new();
                    io::stdin()
                    .read_line(&mut entered_key)
                    .expect("Failed to read input");

                    let input_bytes = validate_aes_key(&entered_key.trim());

                    // Step 2: Copy the first 32 bytes (or pad with 0s if shorter)
                    match input_bytes {
                        Some(valid_key) => {
                            // Copy the validated key into `byte_array`
                            byte_array.copy_from_slice(&valid_key);
                            //println!("AES Key: {:?}", byte_array);
                        }
                        None => {
                            // if invalid input, promt again.
                        }
                    }

                    let key: GenericArray<u8, U32> = GenericArray::from(byte_array);
                    //println!("{:?}", hex::encode(&key));

                    println!("{}",encryption::text_encryption(plaintext, key));
                    }
        "Decrypt Text" => {
                        println!("Enter ciphertext you want to decrypt:");
                        let mut ciphertext = String::new();
                        io::stdin()
                        .read_line(&mut ciphertext)
                        .expect("Failed to read input");

                    println!("Enter a key, or leave empty for randomly generated one.");
                    let mut byte_array = [0u8; 32];
                    let mut entered_key = String::new();
                    io::stdin()
                    .read_line(&mut entered_key)
                    .expect("Failed to read input");

                    let input_bytes = validate_aes_key(&entered_key.trim());

                    // Step 2: Copy the first 32 bytes (or pad with 0s if shorter)
                    match input_bytes {
                        Some(valid_key) => {
                            // Copy the validated key into `byte_array`
                            byte_array.copy_from_slice(&valid_key);
                            //println!("AES Key: {:?}", byte_array);
                        }
                        None => {
                            // if invalid input, promt again.
                        }
                    }

                    let key: GenericArray<u8, U32> = GenericArray::from(byte_array);
                    //println!("{:?}", hex::encode(&key));

                    println!("{}",encryption::text_decryption(ciphertext, key));
                    }
        "Change Password" => {
            println!("Enter current password of your account:");
            let current_password = read_password().expect("Failed to read password");
            let current_password = current_password.trim();

            println!("Enter password you want for your account:");
            let password = read_password().expect("Failed to read password");
            let password = password.trim();

            println!("Enter password again:");
            let password_again = read_password().expect("Failed to read password");
            let password_again = password_again.trim();

            let credentials = read_credential(username_db);
            if argon2::verify_encoded(&credentials.unwrap().secret, current_password.as_bytes()).unwrap() {

                if password.trim() == password_again.trim(){
                    let account_password = Some(password.trim().to_string()); // Store trimmed password as a String

                let credentials = read_credential(username_db);
                let hash_password = argon2::hash_encoded(account_password.clone().unwrap().as_bytes(), salt, &config).unwrap();
                let hash_username = &credentials.unwrap().username;

                let _ = write_credential(username_db, credential::Credential{
                    username: hash_username.to_owned(),
                    secret: hash_password.to_owned(),
                });
                let log_message = format!("Authenticated user successfully changed authentication credentials.");
                log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
                println!("Password changed successfully");
            } else {
                let log_message = format!("Authenticated user failed to update credentials. New Password did not match.");
                log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
                println!("Passwords don't match.");
            }

            } else {
                let log_message = format!("Authenticated user failed to update credentials. User entered wrong password.");
                log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
                println!("Wrong password.");
            }
        }
        "Quit" => {
            println!("Exiting program...");
            let log_message = format!("Authenticated user exited the program.");
            log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
                        quit();
                    }
        _ => {
                        println!("Unknown command.");
            }
        }
    }
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
        let random_data: Vec<u8> = (0..file_size).map(|_| rng.gen::<u8>()).collect();
        file.write_all(&random_data)?;
        file.flush()?;  // Ensure data is written to disk
    }

    // Step 4: Delete the file
    drop(file);  // Close file handle
    let log_message = format!("{} Deleted.", file_path.display());
    log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
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
    let log_message = format!("New AES key generated.");
    log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
    GenericArray::from(key_bytes) // Convert to GenericArray
}

fn help_menu() {
    println!("
    Usable options:
    Generate Key                - Generates randomly an usable 64 bit AES key.
    Help                        - Show help menu that contains the options' explanation.
    Store                       - Store a file to dedicated directory and encrypt it.
    Retrieve                    - Retrieve a file from the dedicated directory and decrypt it and delete it from the directory.
    Encrypt File                - Encrypts a file. Prompts file path and random key generation. Can also be used with your own key.
    Decrypt File                - Decrypts a file encrypted by this software. Prompts file path and key.
    Delete File                 - Secure file deletion, 10 iterations of rewrite before deletion. Prompts file path.
    Encrypt                     - Encrypts a message. Prompts text and key.
    Decrypt                     - Decrypts a message. Prompts text and key.
    Change Password             - Enables you to change your current account's password.
    Quit                        - Quit the program.
    ");
}

fn list_files_in_directory(dir: &Path) {
    match fs::read_dir(dir) {
        Ok(entries) => {
            if dir != Path::new(STORAGE_FILES_DIR){
                println!("Files in {:?}:", dir);
            }
            for entry in entries {
                if let Ok(entry) = entry {
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.is_file() {
                            println!("{}", entry.file_name().to_string_lossy());
                        }
                    }
                }
            }
        }
        Err(err) => {
            eprintln!("Error reading directory: {}", err);
        }
    }
}

fn quit() {
    process::exit(0);
}

fn get_file_with_completion(dir: &Path) -> String {
    let mut file_name = String::new();
    let completions: Vec<String> = match fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.metadata().map(|m| m.is_file()).unwrap_or(false))
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect(),
        Err(_) => Vec::new(),
    };

    println!("Available files: {:?}", completions);
    print!("File name: ");
    io::stdout().flush().unwrap();

    io::stdin()
        .read_line(&mut file_name)
        .expect("Failed to read input");
    let mut file_name = file_name.trim().to_string();

    // Auto-completion logic
    if !completions.is_empty() {
        if let Some(completion) = completions.iter().find(|f| f.starts_with(&file_name)) {
            println!("Auto-completed to: {}", completion);
            file_name = completion.clone();
        } else {
            println!("No matches found for '{}'.", file_name);
        }
    }

    file_name
}

fn log_to_event_viewer(message: &str, event_type: u16) {
    unsafe {
        // Convert the source name to a wide string
        let source_name = U16CString::from_str("MyRustApp").unwrap();
        let handle = RegisterEventSourceW(ptr::null(), source_name.as_ptr());

        if handle.is_null() {
            eprintln!("Failed to register event source");
            return;
        }

        // Convert the log message to a wide string
        let message = U16CString::from_str(message).unwrap();
        let message_ptrs = [message.as_ptr() as *const u16];

        // Write the log to the Event Viewer
        ReportEventW(
            handle,
            event_type, // Event type (e.g., EVENTLOG_INFORMATION_TYPE)
            0,          // Event category
            0x01,       // Event ID
            ptr::null_mut(), // User SID
            message_ptrs.len() as u16, // Number of strings
            0,                        // Data size
            message_ptrs.as_ptr() as *mut *const u16,
            ptr::null_mut(),          // Raw data
        );

        // Deregister the event source
        DeregisterEventSource(handle);
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Write};
    use std::fs::remove_dir_all;

    const TEST_FILES_DIR: &str = "test_files";

    fn create_local_file_with_content(file_name: &str, content: &[u8]) -> std::io::Result<PathBuf> {
        // Ensure the directory exists
        create_dir_all(TEST_FILES_DIR)?;

        let file_path = PathBuf::from(TEST_FILES_DIR).join(file_name);
        let path = PathBuf::from(file_path);
        {
        let mut file = File::create(&path)?; // File is scoped to ensure it gets dropped
        file.write_all(content)?;
        } // File is dropped here
        Ok(path)
    }

    #[test]
    fn test_valid_aes_key() {
        let valid_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let result = validate_aes_key(valid_key);
        assert!(result.is_some(), "Valid key should return Some with the GenericArray");
        assert_eq!(result.unwrap().len(), 32, "The length of the AES key should be 32 bytes");
    }

    #[test]
    fn test_invalid_length_key_too_short() {
        let short_key = "00112233445566778899aabbccddeeff0011223344556677";
        let result = validate_aes_key(short_key);
        assert!(result.is_none(), "Key with less than 64 characters should return None");
    }

    #[test]
    fn test_invalid_length_key_too_long() {
        let long_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00";
        let result = validate_aes_key(long_key);
        assert!(result.is_none(), "Key with more than 64 characters should return None");
    }

    #[test]
    fn test_invalid_hex_key() {
        let invalid_hex_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeefz"; // 'z' is not valid hex
        let result = validate_aes_key(invalid_hex_key);
        assert!(result.is_none(), "Key with invalid hexadecimal characters should return None");
    }

    #[test]
    fn test_empty_key() {
        let empty_key = "";
        let result = validate_aes_key(empty_key);
        assert!(result.is_none(), "Empty key should return None");
    }

    #[test]
    fn test_edge_case_one_character_short() {
        let key_one_short = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeff";
        let result = validate_aes_key(key_one_short);
        assert!(result.is_none(), "Key with 63 characters should return None");
    }

    #[test]
    fn test_edge_case_one_character_long() {
        let key_one_long = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff1";
        let result = validate_aes_key(key_one_long);
        assert!(result.is_none(), "Key with 65 characters should return None");
    }

    //-----------------------------------------------------------------------------------------

    #[test]
    fn test_file_deletion_success() {
        // Arrange: Create a local file with some content
        thread::sleep(Duration::new(1, 0));
        let file_content = b"Test content for file deletion";
        let file_path = create_local_file_with_content("test_deletion_success.txt", file_content).unwrap();

        // Ensure the file exists before calling the function
        assert!(file_path.exists(), "File should exist before deletion");

        // Act: Call the file_deletion function
        let result = file_deletion(file_path.clone());

        // Assert: Ensure the result is Ok and the file is deleted
        assert!(result.is_ok(), "file_deletion should succeed");
        assert!(!file_path.exists(), "File should be deleted after file_deletion");
    }

    #[test]
    fn test_file_deletion_empty_file() {
        // Arrange: Create an empty local file
        thread::sleep(Duration::new(1, 0));
        let file_path = create_local_file_with_content("test_empty_file.txt", b"").unwrap();
        
        // Ensure the file exists before calling the function
        assert!(file_path.exists(), "File should exist before deletion");
        
        // Act: Call the file_deletion function on an empty file
        thread::sleep(Duration::new(1, 0));
        let result = file_deletion(file_path.clone());

        // Assert: Ensure the result is Ok and the file is deleted
        assert!(result.is_ok(), "file_deletion should succeed on an empty file");
        assert!(!file_path.exists(), "File should be deleted after file_deletion");
    }

    #[test]
    fn test_file_deletion_with_random_data() {
        // Arrange: Create a file with random data
        let file_content: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
        let file_path = create_local_file_with_content("test_random_data.txt", &file_content).unwrap();

        // Ensure the file exists before calling the function
        assert!(file_path.exists(), "File should exist before deletion");

        // Act: Call the file_deletion function
        let result = file_deletion(file_path.clone());

        // Assert: Ensure the result is Ok and the file is deleted
        assert!(result.is_ok(), "file_deletion should succeed");
        assert!(!file_path.exists(), "File should be deleted after file_deletion");
    }

    #[test]
    fn test_file_deletion_after_multiple_overwrites() {
        // Arrange: Create a file with content to be overwritten
        let file_content = b"Test content for overwriting";
        thread::sleep(Duration::new(1, 0));
        let file_path = create_local_file_with_content("test_overwrites.txt", file_content).unwrap();

        // Ensure the file exists before calling the function
        assert!(file_path.exists(), "File should exist before deletion");

        // Act: Call the file_deletion function, which overwrites the file multiple times
        let result = file_deletion(file_path.clone());
        
        // Assert: Ensure the result is Ok and the file is deleted
        assert!(result.is_ok(), "file_deletion should succeed after overwriting");
        assert!(!file_path.exists(), "File should be deleted after file_deletion");
    }

    // Cleanup function to remove all test files after tests run
    #[test]
    fn cleanup_test_files() {
        // Clean up the test_files directory
        remove_dir_all(TEST_FILES_DIR).unwrap_or_else(|_| println!("Failed to clean up test files."));
    }

    //---------------------------------------------------------------------------------



}