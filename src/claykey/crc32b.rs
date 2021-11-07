// from https://github.com/wegank/claymore/blob/9056be5a7c846dec37bcb2815841c03c9d4f4aa5/components/key/src/crc32b.rs

use crc::{Crc, CRC_32_BZIP2};

pub fn hash(val: u128) -> u16 {
    let crc = Crc::<u32>::new(&CRC_32_BZIP2);
    let val = val & 0xfff6007fffffffffffffffffffffffff;
    crc.checksum(&val.to_le_bytes()) as u16 & 0x3ff
}

pub fn is_valid(val: u128) -> bool {
    hash(val) == ((val >> 103) as u16) & 0x3ff
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_VAL: u128 = u128::from_le_bytes([
        0xf6, 0x06, 0x00, 0x00, 0x00, 0x00, 0x78, 0xd6,
        0x9d, 0xdc, 0xfa, 0x86, 0x83, 0x26, 0x01, 0x00
    ]);
    const CHECKSUM: u16 = 0x24d;

    #[test]
    fn test_hash() {
        assert_eq!(hash(KEY_VAL), CHECKSUM);
    }

    #[test]
    fn test_is_valid() {
        assert!(is_valid(KEY_VAL));
    }
}