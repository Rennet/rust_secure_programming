use aes::cipher::{generic_array::GenericArray};
use wincredentials::credential::Credential;
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
use base32::encode;
use base32::Alphabet::Rfc4648;
use dialoguer::{theme::ColorfulTheme, Select};
use wincredentials::*;
mod encryption;
use winapi::um::winbase::{RegisterEventSourceW, ReportEventW, DeregisterEventSource};
use widestring::{U16CString};
use wincredentials_bindings::Windows::Win32::{
    Foundation::*, Security::Credentials::*, System::SystemInformation::*,
};
use winapi::um::winnt::EVENTLOG_ERROR_TYPE;
use winapi::um::winnt::EVENTLOG_INFORMATION_TYPE;
use std::panic;
use std::fs::create_dir_all;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::num::NonZeroU32;
use lazy_static;
use resvg::tiny_skia::{Pixmap, Transform};
use resvg::usvg::{Options, Tree};
use minifb::{Key, Window, WindowOptions};
use std::fs::File;
use std::io::ErrorKind;


const NO_FLAGS: u32 = 0;
const GENERIC_CREDENTIAL: u32 = 1;
const STORAGE_FILES_DIR: &str = "C:\\secureprogramming\\";
const SALT_DB : &str = "secureprogramming-user31";
const USERNAME_DB : &str = "secureprogramming-user13";
const SALT_LENGTH: usize = 16;
const DERIVED_KEY_LENGTH: usize = 32;

lazy_static::lazy_static! {
    static ref PBKDF2_ITERATIONS: NonZeroU32 = NonZeroU32::new(100_000).expect("Invalid iterations");
}

#[derive(Debug)]
pub enum FileError {
    FileNotFound,
    InvalidExtension,
    FileTooLarge,
    InvalidPermissions,
    IoError(io::Error),
}

impl From<io::Error> for FileError {
    fn from(error: io::Error) -> Self {
        FileError::IoError(error)
    }
}

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
        let config = Config::default();

        let auth = GoogleAuthenticator::new();

        // Check if database exists, if not, then prompt to registration.
        match read_credential(USERNAME_DB) {
            Ok(credential) => { //credentials exist
                println!("Please authenticate to use this software.");
                println!("Enter username:");
                let mut username = String::new();
                io::stdin()
                .read_line(&mut username)
                .expect("Failed to read input");
            let username = username.trim();

            println!("Enter password:");
            let password = sanitize_password(SecretBox::new(Box::new(read_password().expect("Failed to read password"))))?;
            login(username, password, credential);
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
                let password = sanitize_password(SecretBox::new(Box::new(read_password().expect("Failed to read password"))))?;

                println!("Enter password again:");
                let password_again = sanitize_password(SecretBox::new(Box::new(read_password().expect("Failed to read password"))))?;

            match register(&username, password, password_again, auth, config.clone()) {
                Ok(()) => {
                    //registered
                }
                Err(error) => {
                    //failed
                    println!("Error: {error}");
                    print!("Registration error. Please try again.");
                    quit();
                }
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

fn register(username: &str, password: SecretBox<String>, password_again: SecretBox<String>, auth: GoogleAuthenticator, config: Config<'_> ) -> Result<(), Box<dyn std::error::Error>> {
    if username.len() < 5 {
        return Err("Username is too short, please select a longer one.".to_string().into());
    }

    if password.expose_secret().trim() == password_again.expose_secret().trim(){
        let account_name = Some(username.trim().to_string()); // Store trimmed username as a String
        let account_password = Some(password.expose_secret().trim().to_string()); // Store trimmed password as a String
        let salt_name = account_name.clone().unwrap().to_string() + "1";

        println!("Your username is: {} and your password has been set.", account_name.as_ref().unwrap());
        let log_message = format!("{username} successfully registered.");
        log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);

        let (salt, derived_key) = derive_key_from_password(password, None).expect("Key derivation failed");
        let salt_h = SecretBox::new(Box::new(hex::encode(&salt)));

        let hash_password = argon2::hash_encoded(account_password.clone().unwrap().as_bytes(), salt.as_slice(), &config).unwrap();
        let hash_username = argon2::hash_encoded(account_name.clone().unwrap().as_bytes(), salt.as_slice(), &config).unwrap();
        let hash_salt_name = argon2::hash_encoded(salt_name.clone().as_bytes(), salt.as_slice(), &config).unwrap();
        //set MFA

        let _ = write_credential_custom(USERNAME_DB, Credential{
            username: hash_username.to_owned(),
            secret: hash_password.to_owned(),
        });

        // Convert it to MFA
        let base32_secret = SecretBox::new(Box::new(encode(Rfc4648 { padding: true }, &derived_key)));


        let _ = write_credential_custom(SALT_DB,  Credential{
            username: hash_salt_name.to_owned(),
            secret: salt_h.expose_secret().to_owned(),
        });

            let qr_code = auth.qr_code(base32_secret.expose_secret(), "Secure_Programming", &username, 200, 200, ErrorCorrectionLevel::High).unwrap();


            // Print out the secret to verify it's correct
            // println!("Secret: {}", base32_secret.expose_secret());
            println!("Generating QR code for MFA, please do not close it without scanning it without authenticator! there is no way to get it again.");

            let qr_svg = qr_code.as_bytes(); // The SVG data from `auth.qr_code`
            display_qr_code(qr_svg);

            // Add delay for user to scan the QR code
            thread::sleep(Duration::new(4, 0));
            println!("Did you accidently close it and want it to be displayed again?");
            io::stdout().flush().unwrap();
            let commands = vec![
                "Yes",
                "No",
                ];
                // Display the menu and let the user select a command
                let selection = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Choose a command")
                    .items(&commands)
                    .default(0) // Preselect the first item
                    .interact()
                    .expect("Failed to display menu");
            match commands[selection] {
                "Yes" => {
                        println!("Regenerating QR code.");
                        display_qr_code(qr_svg);
                        return Ok(())
                    }
                    "No" => {//continue
                        }
                    _ => {//continue
                    }
                }
        }
        else {
            return Err("Passwords do not match".to_string().into());
        }
        Ok(())
}

fn login(username: &str, password: SecretBox<String>, credential: Credential) {
    // Verifying credentials
    if argon2::verify_encoded(&credential.username, username.as_bytes()).unwrap() {
        if argon2::verify_encoded(&credential.secret, password.expose_secret().as_bytes()).unwrap() {
            // get the salt
            match read_credential(SALT_DB) {
                Ok(credential) => { //credentials exist
                    //print!("{}", credential.secret);
                    let decoded_secret = match hex::decode(credential.secret) {
                        Ok(decoded) => Some(decoded), // Pass Vec<u8> directly
                        Err(_) => None, // Return None if decoding fails
                    };
                    let Ok((_salt, derived_key)) = derive_key_from_password(password, decoded_secret.as_deref()) else { todo!() };
                    let base32_secret = SecretBox::new(Box::new(encode(Rfc4648 { padding: true }, &derived_key)));
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
                }
                Err(error) => {
                    println!("ERROR IS: {}", error );
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    println!("Authentication failed.");
                    let log_message = format!("{username} Failed to authenticate - MFA not registered however account exists - CONTACT ADMIN.");
                    log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
                    quit();
                }
            }
            // generate the key


        // Successful authentication
    } else {
        std::thread::sleep(std::time::Duration::from_millis(200));
        println!("Authentication failed.");
        let log_message = format!("{username} Failed to authenticate - Wrong credentials.");
        log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
        quit();
    }
    } else {
    std::thread::sleep(std::time::Duration::from_millis(200));
    println!("Authentication failed.");
    let log_message = format!("{username} Failed to authenticate - Wrong credentials.");
    log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
    quit();
    }
}

fn display_qr_code(svg_data: &[u8]) {
    // Parse the SVG data into a tree
    let options = Options::default();
    let tree = Tree::from_data(svg_data, &options).expect("Failed to parse SVG data");

    // Create a Pixmap for rendering
    let pixmap_size = tree.size();
    let mut pixmap = Pixmap::new(pixmap_size.width() as u32, pixmap_size.height() as u32)
        .expect("Failed to create Pixmap");

    // Render the SVG to the Pixmap
    resvg::render(
        &tree,
        Transform::default(),
        &mut pixmap.as_mut(),
    );

    // Prepare the buffer for `minifb`
    let width = pixmap.width();
    let height = pixmap.height();
    let buffer: Vec<u32> = pixmap
        .pixels()
        .iter()
        .map(|p| {
            let color = p; // `to_color` replaces the invalid `color` method
            ((color.red() as u32) << 16) | ((color.green() as u32) << 8) | (color.blue() as u32)
        })
        .collect();

    // Display the PNG in a window
    let mut window = Window::new(
        "QR Code - Scan It!",
        width as usize,
        height as usize,
        WindowOptions::default(),
    )
    .unwrap_or_else(|e| {
        panic!("Unable to create window: {}", e);
    });

    window.set_position(0, 0); // Move window to the top-left corner

    // Ensure the window pops up and stays in the foreground (this depends on the system)
    // Event loop for window interactions
    while window.is_open() && !window.is_key_down(Key::Escape) {
        window
            .update_with_buffer(&buffer, width as usize, height as usize)
            .unwrap();
        window.update(); // Ensure window is updated on each frame.
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
    thread::sleep(Duration::new(1, 0));
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

/// Derives a key from a password using PBKDF2
pub fn derive_key_from_password(password: SecretBox<String>, salt: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Generate a new salt if none is provided
    let salt = match salt {
        Some(s) => s.to_vec(),
        None => {
            let mut salt = vec![0u8; SALT_LENGTH];
            let rng = SystemRandom::new();
            rng.fill(&mut salt).map_err(|_| "Failed to generate salt")?;
            salt
        }
    };

    let mut derived_key = vec![0u8; DERIVED_KEY_LENGTH];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        *PBKDF2_ITERATIONS,
        &salt,
        password.expose_secret().as_bytes(),
        &mut derived_key,
    );

    Ok((salt, derived_key))
}

pub fn write_credential_custom(target: &str, val: Credential) -> Result<(), Box<dyn std::error::Error>> { //Alteration due to persistence
    // Get the current time as a Windows file time
    let filetime = Box::new(FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    });
    let filetime: *mut FILETIME = Box::into_raw(filetime);
    unsafe { GetSystemTimeAsFileTime(filetime) };

    // Convert all the things into UTF16
    let secret_len = val.secret.len();

    let target_cstr = U16CString::from_str(target).unwrap();
    let secret_cstr = U16CString::from_str(val.secret).unwrap();
    let user_cstr = U16CString::from_str(val.username).unwrap();

    let target_ptr = target_cstr.as_ptr();
    let secret_ptr = secret_cstr.as_ptr();
    let user_ptr = user_cstr.as_ptr();

    // Build our credential object
    let cred = CREDENTIALW {
        Flags: CRED_FLAGS(NO_FLAGS),
        Type: CRED_TYPE(GENERIC_CREDENTIAL),
        TargetName: PWSTR(target_ptr as *mut u16),
        Comment: PWSTR(std::ptr::null_mut() as *mut u16),
        LastWritten: unsafe { *filetime },
        CredentialBlobSize: secret_len as u32 * 2,
        CredentialBlob: secret_ptr as *mut u8,
        Persist: CRED_PERSIST(2),
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: PWSTR(std::ptr::null_mut() as *mut u16),
        UserName: PWSTR(user_ptr as *mut u16),
    };

    // Write the credential out
    unsafe { CredWriteW(&cred, NO_FLAGS).ok()? };

    // Free the file time object we got
    unsafe { drop(Box::from_raw(filetime)) }

    Ok(())
}

/// Verify a password against an existing salt and derived key
pub fn verify_password(password: &str, salt: &[u8], expected_key: &[u8]) -> bool {
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        *PBKDF2_ITERATIONS,
        salt,
        password.as_bytes(),
        expected_key,
    )
    .is_ok()
}

pub fn sanitize_file_input(file_path: &str) -> Result<std::path::PathBuf, FileError> {
    let path = Path::new(file_path);

    // 1. Check if file exists
    if !path.exists() {
        return Err(FileError::FileNotFound);
    }

    // 2. Attempt to open the file
    match File::open(path) {
        Ok(_) => {
            // If it opens successfully, check if it's read-only
            let metadata = fs::metadata(path).map_err(|_| FileError::InvalidPermissions)?;
            if metadata.permissions().readonly() {
                return Err(FileError::InvalidPermissions);
            }
            Ok(path.to_path_buf())
        }
        Err(e) => {
            if e.kind() == ErrorKind::PermissionDenied {
                return Err(FileError::InvalidPermissions);
            }
            Err(FileError::FileNotFound)
        }
    }
}

pub fn sanitize_password(password: SecretBox<String>) -> Result<SecretBox<String>, Box<dyn std::error::Error>> {

    let sanitized = SecretBox::new(Box::new(password.expose_secret().trim().to_string())); // Trim whitespace

    if sanitized.expose_secret().len() < 8 {
        return Err("Password has to be at least 8 characters".to_string().into());
    }

    if sanitized.expose_secret().chars().any(|c| c.is_control()) {
        return Err("Password contains invalid control characters.".to_string().into());
    }

    Ok(sanitized)

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Write};
    use rand::distributions::Alphanumeric;
    use std::fs::File;
    use std::fs::remove_dir_all;
    use secrecy::SecretBox;
    use google_authenticator::get_code;
    const TEST_FILES_DIR: &str = "test_files";

    fn register_test(username: &str, password: SecretBox<String>, password_again: SecretBox<String>, base32_secret: SecretBox<String>, auth: GoogleAuthenticator, username_db:&str, config: Config<'_> ) -> Result<(), Box<dyn std::error::Error>> {
        let salt = b"858dc1dfe1f";
        if username.len() < 5 {
            return Err("Username is too short, please select a longer one.".to_string().into());
        }

        if password.expose_secret().trim() == password_again.expose_secret().trim(){
            let account_name = Some(username.trim().to_string()); // Store trimmed username as a String
            let account_password = Some(password.expose_secret().trim().to_string()); // Store trimmed password as a String

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
                // println!("Secret: {}", base32_secret.expose_secret());
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
            else {
                return Err("Passwords do not match".to_string().into());
            }
            Ok(())
    }

    fn login_test(username: &str, password: SecretBox<String>, base32_secret: SecretBox<String>, credential: Credential, code: String) { // INCLUDES MFA CODE, REAL FUNCTION PROMPTS IT
        // Verifying credentials
        if argon2::verify_encoded(&credential.username, username.as_bytes()).unwrap() {
            if argon2::verify_encoded(&credential.secret, password.expose_secret().as_bytes()).unwrap() {
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
                //quit();
            }
            // Successful authentication
        } else {
            std::thread::sleep(std::time::Duration::from_millis(200));
            println!("Authentication failed.");
            let log_message = format!("{username} Failed to authenticate - Wrong credentials.");
            log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
            //quit();
        }
        } else {
        std::thread::sleep(std::time::Duration::from_millis(200));
        println!("Authentication failed.");
        let log_message = format!("{username} Failed to authenticate - Wrong credentials.");
        log_to_event_viewer(&log_message, EVENTLOG_INFORMATION_TYPE);
        //quit();
        }
    }

    fn create_local_file_with_content(file_name: &str, content: &[u8]) -> std::io::Result<PathBuf> {
        // Ensure the directory exists
        fs::create_dir_all(TEST_FILES_DIR)?;

        let file_path = Path::new(TEST_FILES_DIR).join(file_name);
        {
            let mut file = File::create(&file_path)?; // File is scoped to ensure it gets dropped
            file.write_all(content)?;
        } // File is dropped here
        thread::sleep(Duration::new(1, 0));
        Ok(file_path)
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
        thread::sleep(Duration::new(2, 0));

        // Ensure the file exists before calling the function
        assert!(file_path.exists(), "File should exist before deletion");

        // Act: Call the file_deletion function
        let result = file_deletion(file_path.clone());
        thread::sleep(Duration::new(2, 0));

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
    #[test]fn test_register_success() {
        let username = "test_user";
        let password = SecretBox::new(Box::new("secure_password".to_string()));
        let password_again = SecretBox::new(Box::new("secure_password".to_string()));
        let base32_secret = SecretBox::new(Box::new("BASE32SECRET123".to_string()));
        let auth = GoogleAuthenticator::new();
        let config = Config::default();

        let result = register_test(username, password, password_again, base32_secret, auth, "test_db", config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_register_password_mismatch() {
        let username = "test_user";
        let password = SecretBox::new(Box::new("secure_password".to_string()));
        let password_again = SecretBox::new(Box::new("different_password".to_string()));
        let base32_secret = SecretBox::new(Box::new("BASE32SECRET123".to_string()));
        let auth = GoogleAuthenticator::new();
        let config = Config::default();

        let result = register_test(username, password, password_again, base32_secret, auth, "test_db", config);
        assert!(result.is_err());
    }

    #[test]
    fn test_login_success() {
        let username = "test_user";
        let password = SecretBox::new(Box::new("secure_password".to_string()));
        let base32_secret = SecretBox::new(Box::new("BASE32SECRET123".to_string()));
        let credential = Credential {
            username: argon2::hash_encoded(username.as_bytes(), b"salt12345678", &Config::default()).unwrap(),
            secret: argon2::hash_encoded(password.expose_secret().as_bytes(), b"salt12345678", &Config::default()).unwrap(),
        };
        if let Ok(code) = get_code!(base32_secret.expose_secret()) {
            login_test(username, password, base32_secret, credential, code);
        }
    }

    #[test]
    fn test_login_incorrect_password() {
        let username = "test_user";
        let password = SecretBox::new(Box::new("wrong_password".to_string()));
        let base32_secret = SecretBox::new(Box::new("BASE32SECRET123".to_string()));
        let credential = Credential {
            username: argon2::hash_encoded(username.as_bytes(), b"salt12345678", &Config::default()).unwrap(),
            secret: argon2::hash_encoded("secure_password".as_bytes(), b"salt12345678", &Config::default()).unwrap(),
        };
        if let Ok(code) = get_code!(base32_secret.expose_secret()) {
            login_test(username, password, base32_secret, credential, code);
        }
    }

    #[test]
    fn test_register_valid_inputs() {
        let username = "test_user";
        let password = SecretBox::new(Box::new("secure_password".to_string()));
        let password_again = SecretBox::new(Box::new("secure_password".to_string()));
        let base32_secret = SecretBox::new(Box::new("MZXW6YTBOI======".to_string()));
        let auth = GoogleAuthenticator::new();
        let username_db = "test_db.json";
        let config = argon2::Config::default();

        let result = register_test(username, password, password_again, base32_secret, auth, username_db, config);
        assert!(result.is_ok(), "Registration failed unexpectedly: {:?}", result);
    }

    #[test]
    fn test_register_password_mismatch2() {
        let username = "test_user";
        let password = SecretBox::new(Box::new("secure_password".to_string()));
        let password_again = SecretBox::new(Box::new("different_password".to_string()));
        let base32_secret = SecretBox::new(Box::new("MZXW6YTBOI======".to_string()));
        let auth = GoogleAuthenticator::new();
        let username_db = "test_db.json";
        let config = argon2::Config::default();

        let result = register_test(username, password, password_again, base32_secret, auth, username_db, config);
        assert!(result.is_err(), "Registration succeeded despite password mismatch.");
    }

    #[test]
    fn test_register_empty_username() {
        let username = "";
        let password = SecretBox::new(Box::new("secure_password".to_string()));
        let password_again = SecretBox::new(Box::new("secure_password".to_string()));
        let base32_secret = SecretBox::new(Box::new("MZXW6YTBOI======".to_string()));
        let auth = GoogleAuthenticator::new();
        let username_db = "test_db.json";
        let config = argon2::Config::default();

        let result = register_test(username, password, password_again, base32_secret, auth, username_db, config);
        assert!(result.is_err(), "Registration succeeded with empty username.");
    }

    #[test]
    fn test_login_valid_credentials() {
        let username = "test_user";
        let password = SecretBox::new(Box::new("secure_password".to_string()));
        let credential = Credential {
            username: argon2::hash_encoded(username.as_bytes(), b"salt12345678", &argon2::Config::default()).unwrap(),
            secret: argon2::hash_encoded(password.expose_secret().as_bytes(), b"salt12345678", &argon2::Config::default()).unwrap(),
        };
        let base32_secret = SecretBox::new(Box::new("MZXW6YTBOI======".to_string()));

        if let Ok(code) = get_code!(base32_secret.expose_secret()) {
            login_test(username, password, base32_secret, credential, code);
        }
        // If no panic or quit occurs, the test passes
    }

    #[test]
    fn test_login_invalid_password() {
        let username = "test_user";
        let password = SecretBox::new(Box::new("wrong_password".to_string()));
        let credential = Credential {
            username: argon2::hash_encoded(username.as_bytes(), b"salt12345678", &argon2::Config::default()).unwrap(),
            secret: argon2::hash_encoded("secure_password".as_bytes(), b"salt12345678", &argon2::Config::default()).unwrap(),
        };
        let base32_secret = SecretBox::new(Box::new("MZXW6YTBOI======".to_string()));

        if let Ok(code) = get_code!(base32_secret.expose_secret()) {
            login_test(username, password, base32_secret, credential, code);
        }
        // If login fails gracefully without panicking, the test passes
    }

    #[test]
    fn test_login_invalid_username() {
        let username = "nonexistent_user";
        let password = SecretBox::new(Box::new("secure_password".to_string()));
        let credential = Credential {
            username: argon2::hash_encoded("test_user".as_bytes(), b"salt12345678", &argon2::Config::default()).unwrap(),
            secret: argon2::hash_encoded(password.expose_secret().as_bytes(), b"salt12345678", &argon2::Config::default()).unwrap(),
        };
        let base32_secret = SecretBox::new(Box::new("MZXW6YTBOI======".to_string()));

        if let Ok(code) = get_code!(base32_secret.expose_secret()) {
            login_test(username, password, base32_secret, credential, code);
        }
        // If login fails gracefully without panicking, the test passes
    }

    #[test]
    fn test_register_concurrent() {
        let num_threads = 10;
        let username_db = "test_db.json";

        let handles: Vec<_> = (0..num_threads).map(|i| {
            let username = format!("test_user_{}", i);
            let password = SecretBox::new(Box::new("secure_password".to_string()));
            let password_again = SecretBox::new(Box::new("secure_password".to_string()));

            std::thread::spawn(move || {
                let config = argon2::Config::default();
                let base32_secret = SecretBox::new(Box::new("MZXW6YTBOI======".to_string()));
                let auth = GoogleAuthenticator::new();
                let result = register_test(&username, password, password_again, base32_secret, auth, username_db, config);
                assert!(result.is_ok(), "Registration failed for user {}: {:?}", i, result);
            })
        }).collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_sanitize_file_input_file_not_found() {
        // Test a file that doesn't exist
        let result = sanitize_file_input("non_existent_file.txt");
        assert!(matches!(result, Err(FileError::FileNotFound)));
    }

    #[test]
    fn test_sanitize_file_input_file_exists_and_readable() {
        // Create a test file
        let test_file = create_local_file_with_content("test_file.txt", b"test content").unwrap();
        let test_file_path = test_file.to_str().unwrap();

        // Ensure the file is created and available
        assert!(Path::new(test_file_path).exists());

        // Test sanitization
        let result = sanitize_file_input(test_file_path);
        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result.err());
        assert_eq!(result.unwrap(), test_file);

        // Clean up
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_sanitize_file_input_invalid_permissions() {
        // Create a test file
        let test_file = create_local_file_with_content("test_file_no_read.txt", b"test content").unwrap();

        // Set restrictive permissions (read-only for Windows)
        let mut permissions = fs::metadata(&test_file).unwrap().permissions();
        permissions.set_readonly(true); // Set the file as read-only
        fs::set_permissions(&test_file, permissions).unwrap();

        // Test sanitization with read-only permissions
        let result = sanitize_file_input(test_file.to_str().unwrap());
        assert!(matches!(result, Err(FileError::InvalidPermissions)),
            "Expected InvalidPermissions, got: {:?}", result);

        // Clean up: Restore permissions to allow deletion
        let mut permissions = fs::metadata(&test_file).unwrap().permissions();
        permissions.set_readonly(false); // Restore to writable
        fs::set_permissions(&test_file, permissions).unwrap();

        // Remove the file
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_sanitize_password_valid() {
        let password = SecretBox::new(Box::new("  P@ssw0rd!  ".to_string()));
        let result = sanitize_password(password);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().expose_secret(), "P@ssw0rd!");
    }

    #[test]
    fn test_sanitize_password_too_short() {
        let password = SecretBox::new(Box::new("short".to_string()));
        let result = sanitize_password(password);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Password has to be at least 8 characters"
        );
    }

    #[test]
    fn test_sanitize_password_invalid_control_characters() {
        let password = SecretBox::new(Box::new("valid\x07pass".to_string())); // Includes a control character
        let result = sanitize_password(password);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Password contains invalid control characters."
        );
    }
}