#![no_main]
use libfuzzer_sys::fuzz_target;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use your_crate::file_deletion;

fuzz_target!(|data: &[u8]| {
    // Convert the fuzz input to a temporary file path (e.g., use a temporary directory).
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("fuzzed_file");

    // Write initial data to the file to prepare it for deletion
    if let Err(err) = File::create(&file_path).and_then(|mut file| file.write_all(data)) {
        eprintln!("Failed to prepare test file: {:?}", err);
        return; // Skip this iteration if we can't set up the file
    }

    // Call the file_deletion function with the fuzzed file path
    let _ = file_deletion(file_path.clone());

    // temp_dir is automatically cleaned up, so the file should be gone
});
