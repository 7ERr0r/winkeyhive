// Copyright 2019 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later
// Modified 2021 by 7ERr0r

use nt_hive::*;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use zerocopy::*;
pub mod claykey;

fn main() -> Result<(), String> {
    let mut hive_filenames: Vec<PathBuf> = Vec::new();
    if env::args().len() < 2 {
        let media_ubuntu = format!(
            "/media/{}",
            std::env::var("USER").unwrap_or("ubuntu".to_string())
        );

        // TODO: maybe use lsblk command
        let _ignore = search_for_drive_c_in(&media_ubuntu, &mut hive_filenames);
        let _ignore = search_for_drive_c_in("/mnt", &mut hive_filenames);
    } else {
        // Read single hive file.
        let filename = env::args().nth(1).unwrap();
        hive_filenames.push(filename.into());
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
        println!("Searching: {}", path.display());

        {
            let hive_path1: &[&str] = &["Windows", "System32", "config", "SOFTWARE"];
            let hive_path2: &[&str] = &["Windows.old", "System32", "config", "SOFTWARE"];

            let hives = &[hive_path1, hive_path2];
            
            for &hive_path in hives {
                let mut path = entry.path();
                hive_path.iter().for_each(|e| path.push(e));

                if path.exists() {
                    println!("    Found: {}", path.display());
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
    read_hive_slice(&buffer)
}
fn read_hive_slice(hive_slice: &[u8]) -> Result<(), String> {
    // Parse the hive.
    let hive = Hive::new(hive_slice).map_err(|e| format!("Error parsing hive file: {}", e))?;

    // Print the name of the root key node.
    let root_key_node = hive
        .root_key_node()
        .map_err(|e| format!("Error getting root key: {}", e))?;
    //println!("root name: {}", root_key_node.name().unwrap().to_string_lossy());

    let verbose = false;
    let info = get_windows_key_info(root_key_node, verbose)?;
    println!("ProductName: {}", info.product_name);
    println!("  ProductID: {}", info.product_id);
    println!(
        " ProductKey: {}",
        windows_convert_to_key(&info.digital_product_id)
    );

    Ok(())
}

#[derive(Default)]
struct WindowsProductInfo {
    pub product_name: String,
    pub product_id: String,
    //pub product_key: String,
    pub digital_product_id: Vec<u8>,
}

fn windows_convert_to_key(key_source: &[u8]) -> String {
    let key_offset = 52;
    let mut key = Vec::from(&key_source[key_offset..key_offset + 16]);
    // Check if OS is Windows 8
    let is_win_8 = (key[8] / 6) & 1;
    // Key(66)
    key[8] = key[8] & 0xF7 | ((is_win_8 & 2) * 4);

    let key_u128: u128 = u128::from_le_bytes(key.try_into().unwrap());
    let key_str = claykey::base24::encode(key_u128);
    key_str
}

fn get_windows_key_info<'a>(
    root_key_node: nt_hive::KeyNode<&'a nt_hive::Hive<&'a [u8]>, &'a [u8]>,
    verbose: bool,
) -> Result<WindowsProductInfo, String> {
    let target_path = "Microsoft\\Windows NT\\CurrentVersion";

    // currently .subkey() doesn't work...
    // tested 6.11.2021
    let subkey_result = root_key_node.subkey(target_path);
    //.ok_or_else(|| format!("can't find subkey by node.subkey(...): {}", sub_name))?

    let current_version_node: nt_hive::KeyNode<&nt_hive::Hive<&'a [u8]>, &'a [u8]> =
        if subkey_result.is_none() {
            let maybe_found = bruteforce_search(
                &Vec::from(target_path.as_bytes()),
                &mut Vec::new(),
                root_key_node,
                0,
                verbose,
            )?;
            maybe_found.ok_or_else(|| {
                format!(
                    "can't find subkey by bruteforce_search(...): {}",
                    target_path
                )
            })?
        } else {
            let current_version_node = subkey_result
                .unwrap()
                .map_err(|e| format!("Error getting subkey: {}", e))?;

            current_version_node
        };

    // let key_name = product_id_node
    //     .name()
    //     .map_err(|e| format!("Error getting key name: {}", e))?;

    let digital_product_id = current_version_node
        .value("DigitalProductId")
        .ok_or("can't find value: DigitalProductId")?
        .map_err(|e| format!("Error getting value: {}", e))?;
    //println!("found key: {}", key_name);
    //println!("DigitalProductId: {:?}", digital_product_id);
    let binary_data = digital_product_id
        .data()
        .map_err(|e| format!("Error getting binary data: {}", e))?;

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

    let _ignore = fill_product_extras(&mut info, current_version_node);

    Ok(info)
}

fn fill_product_extras<'a>(
    info: &mut WindowsProductInfo,
    current_version_node: nt_hive::KeyNode<&nt_hive::Hive<&'a [u8]>, &'a [u8]>,
) -> Result<(), String> {
    info.product_name = current_version_node
        .value("ProductName")
        .ok_or("not found")?
        .map_err(|e| format!("Error getting value: {}", e))?
        .string_data()
        .map_err(|e| format!("Error getting binary data: {}", e))?;

    info.product_id = current_version_node
        .value("ProductID")
        .ok_or("not found")?
        .map_err(|e| format!("Error getting value: {}", e))?
        .string_data()
        .map_err(|e| format!("Error getting binary data: {}", e))?;

    Ok(())
}

fn bruteforce_search<'a>(
    target_path: &Vec<u8>,
    path: &mut Vec<u8>,
    input_key_node: nt_hive::KeyNode<&'a Hive<&'a [u8]>, &'a [u8]>,
    level: usize,
    verbose: bool,
) -> Result<Option<KeyNode<&'a Hive<&'a [u8]>, &'a [u8]>>, String> {
    // Print the names of subkeys of this node.

    if let Some(subkeys) = input_key_node.subkeys() {
        let subkeys = subkeys.map_err(|e| format!("Error getting subkeys: {}", e))?;

        for key_node in subkeys {
            let key_node = key_node.map_err(|e| format!("Error enumerating key: {}", e))?;
            let key_name = key_node
                .name()
                .map_err(|e| format!("Error getting key name: {}", e))?;

            let len_cached = path.len();
            path.extend_from_slice(key_name.to_string_lossy().as_bytes());

            let is_target_path = path == target_path;

            if is_target_path {
                if verbose {
                    println!("● {}", String::from_utf8_lossy(path));
                }

                // Print the names of the values of this node.
                if let Some(value_iter) = key_node.values() {
                    let value_iter =
                        value_iter.map_err(|e| format!("Error creating value iterator: {}", e))?;

                    for value in value_iter {
                        let value = value.map_err(|e| format!("Error enumerating value: {}", e))?;

                        let mut value_name = value
                            .name()
                            .map_err(|e| format!("Error getting value name: {}", e))?
                            .to_string_lossy();
                        if value_name.is_empty() {
                            value_name.push_str("(Default)");
                        }

                        let value_type = value
                            .data_type()
                            .map_err(|e| format!("Error getting value type: {}", e));

                        if verbose {
                            // First line: Value Name, Data Type, and Data Size
                            println!(
                                "  ○ {} - {:?} - {}",
                                value_name,
                                value_type,
                                value.data_size()
                            );

                            // Second line: The actual Value Data

                            print!("    ");

                            print_value(value_type, value)?;
                        }
                    }
                }
                unsafe {
                    // bug in nt-hive crate... we have to ignore lifetimes
                    // this cast is completely safe but .subkeys() doesn't allow us to do so...
                    let ret_key_node: KeyNode<&'a Hive<&'a [u8]>, &'a [u8]> =
                        std::mem::transmute(key_node);
                    return Ok(Some(ret_key_node));
                }
            }

            {
                // Process subkeys.
                path.push(b'\\');
                let maybe_found =
                    bruteforce_search(target_path, path, key_node, level + 1, verbose)?;
                if maybe_found.is_some() {
                    unsafe {
                        // bug in nt-hive crate... we have to ignore lifetimes
                        // this cast is completely safe but .subkeys() doesn't allow us to do so...
                        let ret_found: KeyNode<&'a Hive<&'a [u8]>, &'a [u8]> =
                            std::mem::transmute(maybe_found.unwrap());
                        return Ok(Some(ret_found));
                    }
                }
            }
            path.truncate(len_cached);
        }
    }

    Ok(None)
}

fn print_value<B>(
    value_type: Result<nt_hive::KeyValueDataType, String>,
    value: nt_hive::KeyValue<&nt_hive::Hive<B>, B>,
) -> Result<(), String>
where
    B: ByteSlice,
{
    match value_type {
        Ok(KeyValueDataType::RegSZ | KeyValueDataType::RegExpandSZ) => {
            let string_data = value
                .string_data()
                .map_err(|e| format!("Error getting string data: {}", e))?;

            println!("{}", string_data);
        }
        Ok(KeyValueDataType::RegBinary) => {
            let binary_data = value
                .data()
                .map_err(|e| format!("Error getting binary data: {}", e))?;

            match binary_data {
                KeyValueData::Small(data) => println!("{:?}", data),
                KeyValueData::Big(_iter) => println!("BIG DATA"),
            }
        }
        Ok(KeyValueDataType::RegDWord | KeyValueDataType::RegDWordBigEndian) => {
            let dword_data = value
                .dword_data()
                .map_err(|e| format!("Error getting DWORD data: {}", e))?;

            println!("{}", dword_data)
        }
        Ok(KeyValueDataType::RegMultiSZ) => {
            let multi_string_data = value
                .multi_string_data()
                .map_err(|e| format!("Error getting multi string data: {}", e))?;

            println!("{:?}", multi_string_data);
        }
        Ok(KeyValueDataType::RegQWord) => {
            let qword_data = value
                .qword_data()
                .map_err(|e| format!("Error getting QWORD data: {}", e))?;

            println!("{}", qword_data);
        }
        _ => {
            println!();
        }
    }
    Ok(())
}
