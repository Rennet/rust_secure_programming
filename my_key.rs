use secrecy::{SecretBox};

pub fn secret_key() -> SecretBox<String> {
    // Create a SecretBox containing the AES key
    let secret_key = SecretBox::new(Box::new("83a335cf2e4ef3e74cfe506d496e97a3e263d012fd3edc0bb8c24a77ffda463f".to_string()));
    
    // Return the SecretBox
    secret_key
}