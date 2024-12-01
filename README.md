# Secure File Encryption and Management System
# ICS0022 Secure Programming Project Documentation

## Introduction
This rust project can be used to encrypt and decrypt files using AES encryption. To use the software authentication is required, upon running you are prompted to register. This software provides secure key generation, file encryption, file decryption, text encryption and text decryption. file encryption and decryption also uses HMAC signing to ensure this file was encrypted or decrypted by this software.

## NB!
This software works only in Windows based devices, **versions 10 or older.**

## Set up

Easiest form of using it, is to download ready built executable.

Since it is a command tool, it requires command line usage, execute it with command:
```
.\secure.exe
```
Enter username you want for your account. It cannot be changed later unless you do full re-install.

Then enter password that you want to have, enter it twice.

Then you are provided with QR code, scan it with your authenticator, that will provide you TOPT. Do it now when you register, once you have registered, **you cannot see that QR code ever again.**



However to build it yourself
[cargo](https://doc.rust-lang.org/cargo/) and [rust](https://www.rust-lang.org/tools/install) must be installed and PATH must be configured.

Download the required filed which are **main.rs, encryption.rs, Cargo.lock, Cargo.toml**

go to the directory they are all located and to verify you have rust and
cargo working, with PATH configured use commands:
```
rustc -V
```
```
cargo -V
```

If both are working and are at **least version 1.82**, there should be no problems with building it.

In the directory you have those files, do:
```
cargo build
```

After some time it should be compiled, compiled file can be accessed in directory where you are and then move to **target** and from there to **debug**

Then there should be executable **secure.exe**

example: as C:\Users\Rennet\OneDrive\Desktop\secure\target\debug\secure.exe

## Usage

Navigate among the options:

### Options


1. Generate Key                - Generates randomly an usable 64 bit AES  key.
2. Help                        - Show help menu that contains the options' explanation.
3. Store                       - Store a file to dedicated directory and encrypt it.
4. Retrieve                    - Retrieve a file from the dedicated directory and decrypt it and delete it from the directory.
5. Encrypt File                - Encrypts a file. Prompts file path and random key generation. Can also be used with your own key.
6. Decrypt File                - Decrypts a file encrypted by this software. Prompts file path and key.
7. Delete File                 - Secure file deletion, 10 iterations of rewrite before deletion. Prompts file path.
8. Encrypt                     - Encrypts a message. Prompts text and key.
9. Decrypt                     - Decrypts a message. Prompts text and key.
10. Quit                        - Quit the program.

Store - Requires existing file what you want to store to C:\Secureprogramming
Retrieve- Requires existing file in C:\Secureprogramming and encryption key.

For encryption activites custom key is optional, there is inbuilt option to generate key during encryption.

## Improvements

Due to deadline approaching close, further improvements are for future. If there are suggestions, feedback is appreciated.