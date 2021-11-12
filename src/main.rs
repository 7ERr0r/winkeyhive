// Copyright 2019 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later
// Modified 2021 by 7ERr0r

use hex_fmt::HexFmt;
use nt_hive::*;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

fn main() -> Result<(), String> {
    let mut hive_filenames: Vec<PathBuf> = Vec::new();
    if let Some(filename) = env::args().nth(1) {
        // Read single hive file.
        hive_filenames.push(filename.into());
    } else {
        let user = std::env::var("USER").unwrap_or("".to_string());
        let media_user = format!("/media/{}", user);

        // TODO: maybe use lsblk command
        if user != "ubuntu" {
            let _ignore = search_for_drive_c_in("/media/ubuntu", &mut hive_filenames);
        }
        let _ignore = search_for_drive_c_in(&media_user, &mut hive_filenames);
        let _ignore = search_for_drive_c_in("/mnt", &mut hive_filenames);
    }

    for filename in hive_filenames {
        read_hive_file(&filename)?;
    }
    Ok(())
}

fn search_for_drive_c_in(path: &str, output_paths: &mut Vec<PathBuf>) -> Result<(), String> {
    let paths = std::fs::read_dir(path).map_err(|_| "can't read dir")?;

    for entry in paths {
        let entry = entry.map_err(|_| "can't get dir entry")?;
        let path = entry.path();
        eprintln!("Searching: {}", path.display());

        {
            let hive_path1: &[&str] = &["Windows", "System32", "config", "SOFTWARE"];
            let hive_path2: &[&str] = &["Windows.old", "System32", "config", "SOFTWARE"];

            let hives = &[hive_path1, hive_path2];
            for &hive_path in hives {
                let mut path = entry.path();
                hive_path.iter().for_each(|e| path.push(e));

                if path.exists() {
                    eprintln!("    Found: {}", path.display());
                    output_paths.push(path);
                }
            }
        }
    }

    Ok(())
}

fn read_hive_file(file_path: &PathBuf) -> Result<(), String> {
    let buffer = {
        let mut f = File::open(file_path).map_err(|e| format!("Error opening hive file: {}", e))?;
        let mut buffer = Vec::<u8>::new();
        f.read_to_end(&mut buffer)
            .map_err(|e| format!("Error reading hive file: {}", e))?;

        // closes the file here
        buffer
    };
    read_hive_slice(file_path, &buffer)
}
fn read_hive_slice(file_path: &PathBuf, hive_slice: &[u8]) -> Result<(), String> {
    // Parse the hive.
    let hive = Hive::without_validation(hive_slice)
        .map_err(|e| format!("Error parsing hive file: {}", e))?;

    // Sometimes sequence numbers are mismatched
    // eg. when windows hibernates or loses power
    let validation = hive.validate();
    if let Err(err) = validation {
        eprintln!("warn: hive.validate(): {}", err);
    }

    // Print the name of the root key node.
    let root_key_node = hive
        .root_key_node()
        .map_err(|e| format!("Error getting root key: {}", e))?;

    let mut info = get_windows_key_info(root_key_node)?;
    info.hive_path = file_path.as_os_str().to_string_lossy().to_string();
    println!("");
    println!("Hive path:\t{}", info.hive_path);
    println!("DigitalProduct\t{:?}", HexFmt(&info.digital_product_id));
    println!("ProductName:\t{}", info.product_name);
    println!("ProductID:\t{}", info.product_id);
    println!(
        "Win10 Key:\t{}",
        decode_product_key_win8_plus(&info.digital_product_id, true)
    );
    println!(
        "Win8 Key:\t{}",
        decode_product_key_win8_plus(&info.digital_product_id, false)
    );

    Ok(())
}

#[derive(Default)]
struct WindowsProductInfo {
    pub hive_path: String,
    pub product_name: String,
    pub product_id: String,
    //pub product_key: String,
    pub digital_product_id: Vec<u8>,
}

// https://github.com/mrpeardotnet/WinProdKeyFinder/blob/master/WinProdKeyFind/KeyDecoder.cs#L115
pub fn decode_product_key_win8_plus(digital_product_id: &[u8], check_win8: bool) -> String {
    let key_offset = 52;
    let mut offset_id = Vec::from(&digital_product_id[key_offset..]);
    let mut key = Vec::new();
    if check_win8 {
        let is_win8 = (offset_id[14] / 6) & 1;
        offset_id[14] = (offset_id[14] & 0xf7) | (is_win8 & 2) * 4;
    }
    let mut cur: u32 = 0;
    for _ in 0..25 {
        cur = 0;
        for j in (0..=14 as usize).rev() {
            cur = offset_id[j] as u32 + cur * 256;
            offset_id[j] = (cur / 24) as u8;
            cur = cur % 24;
        }
        key.push(b"BCDFGHJKMPQRTVWXY2346789"[cur as usize]);
    }
    key.reverse();

    if check_win8 {
        key.insert((cur + 1) as usize, b'N');
        key.remove(0);
    }

    return insert_dashes(&String::from_utf8_lossy(&key));
}

fn insert_dashes(key: &str) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        &key[0..5],
        &key[5..10],
        &key[10..15],
        &key[15..20],
        &key[20..]
    )
}

fn get_windows_key_info<'a>(
    root_key_node: nt_hive::KeyNode<&'a nt_hive::Hive<&'a [u8]>, &'a [u8]>,
) -> Result<WindowsProductInfo, String> {
    let target_path = "Microsoft\\Windows NT\\CurrentVersion";

    let current_version_node = root_key_node
        .subpath(target_path)
        .ok_or_else(|| format!("can't find node.subpath({})", target_path))?
        .map_err(|e| format!("error getting node.subpath({}): {}", target_path, e))?;

    let digital_product_id = current_version_node
        .value("DigitalProductId")
        .ok_or("can't find value: DigitalProductId")?
        .map_err(|e| format!("Error getting value: {}", e))?;

    let binary_data = digital_product_id
        .data()
        .map_err(|e| format!("Error getting digital_product_id.data(): {}", e))?;

    let mut final_key_bytes = Vec::new();
    match binary_data {
        KeyValueData::Small(data) => {
            final_key_bytes.extend_from_slice(data);
        }
        KeyValueData::Big(_iter) => {
            return Err(format!("DigitalProductId is KeyValueData::Big ???"));
        }
    }

    let mut info = WindowsProductInfo::default();
    info.digital_product_id = final_key_bytes;

    let extras_result = fill_product_extras(&mut info, current_version_node);
    if let Err(err) = extras_result {
        eprintln!("warn: fill_product_extras: {}", err);
    }

    Ok(info)
}

fn fill_product_extras<'a>(
    info: &mut WindowsProductInfo,
    current_version_node: nt_hive::KeyNode<&nt_hive::Hive<&'a [u8]>, &'a [u8]>,
) -> Result<(), String> {
    info.product_name = node_value_string(&current_version_node, "ProductName")?;
    info.product_id = node_value_string(&current_version_node, "ProductID")?;
    Ok(())
}

fn node_value_string<'a>(
    node: &KeyNode<&Hive<&'a [u8]>, &'a [u8]>,
    value_name: &str,
) -> Result<String, String> {
    node.value(value_name)
        .ok_or_else(|| format!("not found value_name: {}", value_name))?
        .map_err(|e| format!("Error getting value ({}): {}", value_name, e))?
        .string_data()
        .map_err(|e| format!("Error getting binary data ({}): {}", value_name, e))
}
