// from https://github.com/wegank/claymore/blob/9056be5a7c846dec37bcb2815841c03c9d4f4aa5/components/key/src/base24.rs


const BASE24_STR: &str = "BCDFGHJKMPQRTVWXY2346789";
const KEY_INVALID: &str = "Invalid product key.";

pub fn decode(key: &str) -> Result<u128, String> {
    Ok(b24decode(&serialize(key)?))
}

pub fn encode(val: u128) -> String {
    deserialize(&b24encode(val))
}

fn b24decode(bytes: &[u8; 25]) -> u128 {
    let mut val = 0;
    for i in 0..25 {
        val = val * 24 + bytes[i] as u128;
    }
    val
}

fn b24encode(val: u128) -> [u8; 25] {
    let mut val = val;
    let mut bytes: [u8; 25] = [0; 25];
    for i in (0..25).rev() {
        bytes[i] = (val % 24) as u8;
        val = val / 24;
    }
    bytes
}

fn serialize(key: &str) -> Result<[u8; 25], String> {
    let mut key: Vec<char> = key.chars().collect();
    if key.len() != 29 || (5..29).step_by(6).any(|i| key[i] != '-') {
        return Err(KEY_INVALID.to_string());
    }
    key = (0..=29).step_by(6).map(|i| &key[i..i + 5]).collect::<Vec<_>>().concat();
    let mut bytes: [u8; 25] = [0; 25];
    bytes[0] = match key.iter().position(|&c| c == 'N') {
        Some(24) => return Err(KEY_INVALID.to_string()),
        Some(i) => i as u8,
        _ => return Err(KEY_INVALID.to_string()),
    };
    key.remove(bytes[0] as usize);
    for i in 1..25 {
        match BASE24_STR.find(key[i - 1]) {
            Some(pos) => bytes[i] = pos as u8,
            _ => return Err(KEY_INVALID.to_string()),
        }
    }
    Ok(bytes)
}

fn deserialize(bytes: &[u8; 25]) -> String {
    let mut key: String = bytes[1..25].iter()
        .map(|&i| BASE24_STR.as_bytes()[i as usize] as char).collect();
    key.insert(bytes[0] as usize, 'N');
    for &i in [5, 11, 17, 23].iter() {
        key.insert(i, '-');
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "RR3BN-3YY9P-9D7FC-7J4YF-QGJXW";
    const KEY_BYTES: [u8; 25] = [
        0x04, 0x0b, 0x0b, 0x12, 0x00,
        0x12, 0x10, 0x10, 0x17, 0x09,
        0x17, 0x02, 0x15, 0x03, 0x01,
        0x15, 0x06, 0x13, 0x10, 0x03,
        0x0a, 0x04, 0x06, 0x0f, 0x0e
    ];
    const KEY_VAL: u128 = u128::from_le_bytes([
        0xf6, 0x06, 0x00, 0x00, 0x00, 0x00, 0x78, 0xd6,
        0x9d, 0xdc, 0xfa, 0x86, 0x83, 0x26, 0x01, 0x00
    ]);

    #[test]
    fn test_decode() {
        assert_eq!(decode(KEY), Ok(KEY_VAL));
    }

    #[test]
    fn test_encode() {
        assert_eq!(encode(KEY_VAL), KEY.to_string());
    }

    #[test]
    fn test_b24decode() {
        assert_eq!(b24decode(&KEY_BYTES), KEY_VAL);
    }

    #[test]
    fn test_b24encode() {
        assert_eq!(b24encode(KEY_VAL), KEY_BYTES);
    }

    #[test]
    fn test_serialize() {
        assert_eq!(serialize(KEY), Ok(KEY_BYTES));
    }

    #[test]
    fn test_deserialize() {
        assert_eq!(deserialize(&KEY_BYTES), KEY.to_string());
    }
}