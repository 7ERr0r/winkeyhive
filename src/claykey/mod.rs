// Thanks to wegank / claymore
//
// https://github.com/wegank/claymore/blob/9056be5a7c846dec37bcb2815841c03c9d4f4aa5/components/key/src/lib.rs

pub mod base24;
pub mod crc32b;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct KeyInfo {
    pub group_id: u32,
    pub serial_number: u32,
    pub fst_security_value: u64,
    pub snd_security_value: u32,
    pub checksum: u16,
    pub upgrade_bit: u8,
}

impl KeyInfo {
    pub fn load(key: &str) -> Result<KeyInfo, String> {
        let val = base24::decode(key)?;
        Ok(KeyInfo {
            group_id: (val & 0xfffff) as u32,
            serial_number: ((val >> 20) & 0x3fffffff) as u32,
            fst_security_value: ((val >> 50) & 0xffffffffff) as u64,
            snd_security_value: ((val >> 90) & 0x1fff) as u32,
            checksum: ((val >> 103) & 0x3ff) as u16,
            upgrade_bit: (val >> 113) as u8
        })
    }

    fn val(&self) -> u128 {
        self.group_id as u128
            | (self.serial_number as u128) << 20
            | (self.fst_security_value as u128) << 50
            | (self.snd_security_value as u128) << 90
            | (self.checksum as u128) << 103
            | (self.upgrade_bit as u128) << 113
    }

    pub fn is_valid(&self) -> bool {
        crc32b::is_valid(self.val())
            && self.group_id <= 0xfffff
            && self.serial_number <= 0x3fffffff
            && self.fst_security_value <= 0xffffffffff
            && self.snd_security_value <= 0x1fff
            && self.checksum <= 0x3ff
            && self.upgrade_bit <= 0x1
    }

    pub fn hash(&self) -> KeyInfo {
        let mut key_info = self.clone();
        key_info.checksum = crc32b::hash(key_info.val());
        key_info
    }

    pub fn save(&self) -> String {
        base24::encode(self.val())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "RR3BN-3YY9P-9D7FC-7J4YF-QGJXW";
    const KEY_VAL: u128 = u128::from_le_bytes([
        0xf6, 0x06, 0x00, 0x00, 0x00, 0x00, 0x78, 0xd6,
        0x9d, 0xdc, 0xfa, 0x86, 0x83, 0x26, 0x01, 0x00
    ]);
    const KEY_INFO: KeyInfo = KeyInfo {
        group_id: 0x6f6,
        serial_number: 0x0,
        fst_security_value: 0xbeb727759e,
        snd_security_value: 0xe1,
        checksum: 0x24d,
        upgrade_bit: 0x0,
    };

    #[test]
    fn test_load() {
        assert_eq!(KeyInfo::load(KEY), Ok(KEY_INFO));
    }

    #[test]
    fn test_val() {
        assert_eq!(KEY_INFO.val(), KEY_VAL);
    }

    #[test]
    fn test_check() {
        assert!(KEY_INFO.is_valid());
    }

    #[test]
    fn test_hash() {
        assert_eq!(KEY_INFO.hash(), KEY_INFO);
    }

    #[test]
    fn test_save() {
        assert_eq!(KEY_INFO.save(), KEY.to_string());
    }
}