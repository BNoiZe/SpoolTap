//! Creality CFS RFID tags (format from github.com/DnG-Crafts/K2-RFID).
//!
//! MIFARE Classic 1K. Sector 1 (blocks 4-6): first 48 chars of the payload, AES-128-ECB encrypted,
//! sector keys A/B = AES(uid x4)[0..6]. Sector 2 (blocks 8-10): the rest, plain, default key.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use serde::Serialize;

const KEY_KEY: &[u8; 16] = b"q3bu^t1nqfZ(pf$1";
const DATA_KEY: &[u8; 16] = b"H@CFkRnz@KAtBJp2";
const BLANK: [u8; 6] = [0xFF; 6];

fn aes_ecb(key: &[u8; 16], data: &[u8], decrypt: bool) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = data.to_vec();
    for block in out.chunks_exact_mut(16) {
        let b = GenericArray::from_mut_slice(block);
        if decrypt { cipher.decrypt_block(b) } else { cipher.encrypt_block(b) }
    }
    out
}

pub fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()).collect()
}

pub fn sector_key(uid: &[u8]) -> [u8; 6] {
    let block: Vec<u8> = (0..16).map(|i| uid[i % 4]).collect();
    aes_ecb(KEY_KEY, &block, false)[..6].try_into().unwrap()
}

/// date AB124 | vendor 0276 | batch A2 | "1"+material id | "0"+RRGGBB | length m (330 per kg) | serial | reserve
pub fn payload(material_id: &str, color_hex: &str, weight_g: f64, serial: u32) -> String {
    payload_meters(material_id, color_hex, (weight_g / 1000.0 * 330.0) as i64, serial)
}

/// Same record with the length given directly (copying a tag keeps its exact length).
pub fn payload_meters(material_id: &str, color_hex: &str, meters: i64, serial: u32) -> String {
    let hex: String = color_hex.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_uppercase();
    let color = format!("{:0<6}", hex).chars().take(6).collect::<String>();
    let meters = meters.clamp(0, 9999);
    format!("AB1240276A21{material_id}0{color}{meters:04}{:06}000000", serial % 1_000_000)
}

#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct CfsInfo {
    pub material_id: String,
    pub material: String,
    pub color_hex: String,
    pub meters: u32,
    pub serial: u32,
}

/// Inverse of `payload`; None if the text isn't a Creality record.
pub fn parse(text: &str) -> Option<CfsInfo> {
    let c: Vec<char> = text.chars().collect();
    let s = |a: usize, b: usize| c[a..b].iter().collect::<String>();
    if c.len() < 34 || s(5, 9) != "0276" || c[11] != '1' {
        return None;
    }
    let material_id = s(12, 17);
    Some(CfsInfo {
        material: material_name(&material_id),
        material_id,
        color_hex: s(18, 24),
        meters: s(24, 28).parse().ok()?,
        serial: s(28, 34).parse().ok()?,
    })
}

pub fn material_name(id: &str) -> String {
    MATERIALS.iter().find(|m| m.0 == id).map(|m| m.2.to_string()).unwrap_or_else(|| format!("Material {id}"))
}

/// Brand-specific CFS profile if vendor+name match one, else Generic of the same material, else Generic PLA.
pub fn suggest(vendor: &str, name: &str, material: &str) -> &'static str {
    let full = format!("{vendor} {name}").to_lowercase();
    let mat = material.trim().to_uppercase();
    MATERIALS
        .iter()
        .filter(|m| {
            m.1 != "Generic"
                && full.contains(&m.1.to_lowercase())
                && full.contains(&m.2.to_lowercase())
                && (m.3.to_uppercase() == mat || mat.is_empty())
        })
        .max_by_key(|m| m.2.len())
        .or_else(|| MATERIALS.iter().find(|m| m.1 == "Generic" && m.3.to_uppercase() == mat))
        .map(|m| m.0)
        .unwrap_or("00001")
}

/// Raw APDU exchange with the reader (ACR122U pseudo-APDUs for MIFARE Classic).
pub trait Apdu {
    fn tx(&self, apdu: &[u8]) -> Result<Vec<u8>, String>;

    fn ok(r: &[u8]) -> bool where Self: Sized { r.ends_with(&[0x90, 0x00]) }

    fn auth(&self, block: u8, key: &[u8; 6]) -> Result<bool, String> where Self: Sized {
        let mut load = vec![0xFF, 0x82, 0x00, 0x00, 0x06];
        load.extend_from_slice(key);
        if !Self::ok(&self.tx(&load)?) {
            return Err("Schlüssel laden fehlgeschlagen".into());
        }
        Ok(Self::ok(&self.tx(&[0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x60, 0x00])?))
    }
    fn read(&self, block: u8) -> Result<[u8; 16], String> where Self: Sized {
        let r = self.tx(&[0xFF, 0xB0, 0x00, block, 0x10])?;
        if !Self::ok(&r) || r.len() != 18 {
            return Err(format!("Block {block} nicht lesbar"));
        }
        Ok(r[..16].try_into().unwrap())
    }
    fn write(&self, block: u8, data: &[u8]) -> Result<(), String> where Self: Sized {
        let mut apdu = vec![0xFF, 0xD6, 0x00, block, 0x10];
        apdu.extend_from_slice(data);
        if Self::ok(&self.tx(&apdu)?) { Ok(()) } else { Err(format!("Block {block} nicht schreibbar")) }
    }
    /// A failed auth halts the tag; InListPassiveTarget selects it again.
    fn reselect(&self) where Self: Sized {
        let _ = self.tx(&[0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x00]);
    }
}

fn check_uid(uid: &[u8]) -> Result<(), String> {
    if uid.len() == 4 { Ok(()) } else { Err("Kein MIFARE-Classic-1K-Tag".into()) }
}

/// Only rewrite a factory trailer; other access bits could lock the sector for good.
fn set_trailer_keys<C: Apdu>(c: &C, key: &[u8; 6]) -> Result<(), String> {
    let mut t = c.read(7)?;
    if t[6..9] != [0xFF, 0x07, 0x80] {
        return Err("Unerwartete Zugriffsbits in Sektor 1".into());
    }
    t[..6].copy_from_slice(key);
    t[10..].copy_from_slice(key);
    c.write(7, &t)
}

/// Authenticate sector 1 with the CFS key, else the factory key. Returns whether the CFS key worked.
fn open_sector1<C: Apdu>(c: &C, key: &[u8; 6]) -> Result<bool, String> {
    if c.auth(4, key)? {
        return Ok(true);
    }
    c.reselect();
    if c.auth(4, &BLANK)? { Ok(false) } else { Err("Tag nutzt unbekannte Schlüssel".into()) }
}

pub fn write<C: Apdu>(c: &C, uid: &[u8], text: &str) -> Result<(), String> {
    check_uid(uid)?;
    let key = sector_key(uid);
    let data = format!("{text:<96}").into_bytes();
    let already = open_sector1(c, &key)?;
    let s1 = aes_ecb(DATA_KEY, &data[..48], false);
    for i in 0..3 {
        c.write(4 + i as u8, &s1[i * 16..(i + 1) * 16])?;
    }
    if !already {
        set_trailer_keys(c, &key)?;
    }
    if !c.auth(8, &BLANK)? {
        return Err("Sektor 2 nicht zugänglich".into());
    }
    for i in 0..3 {
        c.write(8 + i as u8, &data[48 + i * 16..48 + (i + 1) * 16])?;
    }
    Ok(())
}

/// Ok(None) = readable but no CFS data (blank tag or another format).
pub fn read<C: Apdu>(c: &C, uid: &[u8]) -> Result<Option<CfsInfo>, String> {
    if uid.len() != 4 {
        return Ok(None);
    }
    if !c.auth(4, &sector_key(uid))? {
        c.reselect();
        return Ok(None);
    }
    let mut s1 = Vec::with_capacity(48);
    for b in 4..=6 {
        s1.extend_from_slice(&c.read(b)?);
    }
    Ok(parse(&String::from_utf8_lossy(&aes_ecb(DATA_KEY, &s1, true))))
}

/// Erase sectors 1-2 and restore factory keys in sector 1 (mirrors K2-RFID's "Format").
pub fn wipe<C: Apdu>(c: &C, uid: &[u8]) -> Result<(), String> {
    check_uid(uid)?;
    let key = sector_key(uid);
    let was_cfs = open_sector1(c, &key)?;
    for b in 4..=6 {
        c.write(b, &[0; 16])?;
    }
    if was_cfs {
        set_trailer_keys(c, &BLANK)?;
    }
    if !c.auth(8, &BLANK)? {
        return Err("Sektor 2 nicht zugänglich".into());
    }
    for b in 8..=10 {
        c.write(b, &[0; 16])?;
    }
    Ok(())
}

/// Creality K2 material database (github.com/DnG-Crafts/K2-RFID db/k2.json): (id, brand, name, type).
pub const MATERIALS: &[(&str, &str, &str, &str)] = &[
    ("00004", "Generic", "Generic ABS", "ABS"),
    ("00007", "Generic", "Generic ASA", "ASA"),
    ("00033", "Generic", "Generic ASA-CF", "ASA-CF"),
    ("00010", "Generic", "Generic BVOH", "BVOH"),
    ("00012", "Generic", "Generic HIPS", "HIPS"),
    ("00008", "Generic", "Generic PA", "PA"),
    ("00009", "Generic", "Generic PA-CF", "PA-CF"),
    ("00025", "Generic", "Generic PA12-CF", "PA-CF"),
    ("00015", "Generic", "Generic PA6-CF", "PA6-CF"),
    ("00034", "Generic", "Generic PA6-GF", "PA-GF"),
    ("00022", "Generic", "Generic PA612-CF", "PA-CF"),
    ("00016", "Generic", "Generic PAHT-CF", "PAHT-CF"),
    ("00021", "Generic", "Generic PC", "PC"),
    ("00032", "Generic", "Generic PCTG", "PCTG"),
    ("00020", "Generic", "Generic PET", "PET"),
    ("00013", "Generic", "Generic PET-CF", "PET-CF"),
    ("00003", "Generic", "Generic PETG", "PETG"),
    ("00014", "Generic", "Generic PETG-CF", "PETG-CF"),
    ("00027", "Generic", "Generic PETG-GF", "PETG-GF"),
    ("00001", "Generic", "Generic PLA", "PLA"),
    ("00006", "Generic", "Generic PLA-CF", "PLA-CF"),
    ("00002", "Generic", "Generic PLA-Silk", "PLA"),
    ("00019", "Generic", "Generic PP", "PP"),
    ("00031", "Generic", "Generic PP-CF", "PP-CF"),
    ("00017", "Generic", "Generic PPS", "PPS"),
    ("00018", "Generic", "Generic PPS-CF", "PPS-CF"),
    ("00011", "Generic", "Generic PVA", "PVA"),
    ("00023", "Generic", "Generic Support for PA", "PA"),
    ("00024", "Generic", "Generic Support for PLA", "PLA"),
    ("00005", "Generic", "Generic TPU", "TPU"),
    ("00026", "Generic", "Generic TPU 64D", "TPU"),
    ("07001", "Creality", "CR-ABS", "ABS"),
    ("11001", "Creality", "CR-Nylon", "PA"),
    ("06001", "Creality", "CR-PETG", "PETG"),
    ("04001", "Creality", "CR-PLA", "PLA"),
    ("13001", "Creality", "CR-PLA Carbon", "PLA-CF"),
    ("15001", "Creality", "CR-PLA Fluo", "PLA"),
    ("14001", "Creality", "CR-PLA Matte", "PLA"),
    ("05001", "Creality", "CR-Silk", "PLA"),
    ("16001", "Creality", "CR-TPU", "TPU"),
    ("17001", "Creality", "CR-Wood", "PLA"),
    ("09001", "Creality", "EN-PLA+", "PLA"),
    ("09002", "Creality", "ENDER FAST PLA", "PLA"),
    ("08001", "Creality", "Ender-PLA", "PLA"),
    ("18001", "Creality", "HP Ultra PLA", "PLA"),
    ("19001", "Creality", "HP-ASA", "ASA"),
    ("10001", "Creality", "HP-TPU", "TPU"),
    ("03001", "Creality", "Hyper ABS", "ABS"),
    ("01002", "Creality", "Hyper L-W PLA", "PLA"),
    ("29001", "Creality", "Hyper Marble", "PLA"),
    ("12005", "Creality", "Hyper PA6-CF", "PA6-CF"),
    ("12004", "Creality", "Hyper PA612-CF", "PA612-CF"),
    ("12003", "Creality", "Hyper PAHT-CF", "PA-CF"),
    ("07002", "Creality", "Hyper PC", "PC"),
    ("06002", "Creality", "Hyper PETG", "PETG"),
    ("06003", "Creality", "Hyper PETG-CF", "PETG-CF"),
    ("01001", "Creality", "Hyper PLA", "PLA"),
    ("02001", "Creality", "Hyper PLA-CF", "PLA-CF"),
    ("12002", "Creality", "Hyper PPA-CF", "PA-CF"),
    ("01004", "Creality", "Hyper Stardust", "PLA"),
    ("01601", "Creality", "Soleyin Ultra PLA", "PLA"),
    ("P1003", "Polymaker", "Panchroma PLA Matte", "PLA"),
    ("P1001", "Polymaker", "Panchroma PLA Satin", "PLA"),
    ("P1002", "Polymaker", "PolySonic PLA Pro", "PLA"),
    ("E1001", "eSUN", "PLA+", "PLA"),
    ("00035", "eSUN", "PLA-LW", "PLA"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    // Vectors computed with openssl from the K2-RFID keys.
    #[test]
    fn crypto_and_payload() {
        assert_eq!(sector_key(&[1, 2, 3, 4]).to_vec(), hex_bytes("440CEF12B194"));
        let p = payload("00001", "ff0000", 1000.0, 42);
        assert_eq!(p, "AB1240276A21000010FF00000330000042000000");
        let enc = aes_ecb(DATA_KEY, format!("{p:<48}").as_bytes(), false);
        assert_eq!(enc[..16].to_vec(), hex_bytes("E7399BFFFE09D37BB07CC5C4C17DC9FA"));
        assert!(payload("00001", "#abc", 750.0, 1).starts_with("AB1240276A21000010ABC0000247"));
        let copy = parse(&payload_meters("01001", "C12E1F", 274, 12)).unwrap();
        assert_eq!((copy.meters, copy.serial, copy.material.as_str()), (274, 12, "Hyper PLA"));
        let back = parse(&String::from_utf8_lossy(&aes_ecb(DATA_KEY, &enc, true))).unwrap();
        assert_eq!((back.material_id.as_str(), back.meters, back.serial), ("00001", 330, 42));
        assert!(parse("AB1240276A21000010FF0000033000004").is_none());
        assert!(parse(&" ".repeat(48)).is_none());
    }

    #[test]
    fn material_suggestions() {
        assert_eq!(suggest("Creality", "Hyper PLA", "PLA"), "01001");
        assert_eq!(material_name(suggest("Prusa", "Galaxy", "petg")), "Generic PETG");
        assert_eq!(suggest("", "", "Unobtainium"), "00001");
    }

    /// In-memory MIFARE Classic 1K speaking the ACR122U pseudo-APDUs.
    struct FakeTag { blocks: RefCell<HashMap<u8, [u8; 16]>>, authed: RefCell<Option<u8>>, key: RefCell<[u8; 6]>, halted: RefCell<bool> }
    impl FakeTag {
        fn blank() -> Self {
            let mut b = HashMap::new();
            for s in 0..16u8 {
                b.insert(s * 4 + 3, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            }
            FakeTag { blocks: RefCell::new(b), authed: RefCell::new(None), key: RefCell::new([0; 6]), halted: RefCell::new(false) }
        }
    }
    impl Apdu for FakeTag {
        fn tx(&self, a: &[u8]) -> Result<Vec<u8>, String> {
            let okv = vec![0x90, 0x00];
            match (a[0], a[1]) {
                (0xFF, 0x82) => { self.key.borrow_mut().copy_from_slice(&a[5..11]); Ok(okv) }
                (0xFF, 0x00) => { *self.halted.borrow_mut() = false; Ok(okv) }
                (0xFF, 0x86) => {
                    let block = a[7];
                    let trailer = self.blocks.borrow()[&(block / 4 * 4 + 3)];
                    if !*self.halted.borrow() && trailer[..6] == *self.key.borrow() {
                        *self.authed.borrow_mut() = Some(block / 4); Ok(okv)
                    } else { *self.halted.borrow_mut() = true; *self.authed.borrow_mut() = None; Ok(vec![0x63, 0x00]) }
                }
                (0xFF, 0xB0) | (0xFF, 0xD6) => {
                    let block = a[3];
                    if *self.authed.borrow() != Some(block / 4) { return Ok(vec![0x63, 0x00]); }
                    if a[1] == 0xB0 {
                        let mut r = self.blocks.borrow().get(&block).copied().unwrap_or([0; 16]).to_vec();
                        if block % 4 == 3 { r[..6].fill(0) } // key A never reads back
                        r.extend_from_slice(&okv); Ok(r)
                    } else {
                        self.blocks.borrow_mut().insert(block, a[5..21].try_into().unwrap()); Ok(okv)
                    }
                }
                _ => Err("unknown".into()),
            }
        }
    }

    #[test]
    fn write_read_wipe_roundtrip() {
        let tag = FakeTag::blank();
        let uid = [0x1A, 0x2B, 0x3C, 0x4D];
        assert_eq!(read(&tag, &uid).unwrap(), None);
        write(&tag, &uid, &payload("01001", "C12E1F", 1000.0, 12)).unwrap();
        assert_eq!(tag.blocks.borrow()[&7][..6], sector_key(&uid));
        let info = read(&tag, &uid).unwrap().unwrap();
        assert_eq!((info.material.as_str(), info.color_hex.as_str(), info.serial), ("Hyper PLA", "C12E1F", 12));
        write(&tag, &uid, &payload("00003", "000000", 500.0, 13)).unwrap(); // rewrite with CFS key
        assert_eq!(read(&tag, &uid).unwrap().unwrap().meters, 165);
        wipe(&tag, &uid).unwrap();
        assert_eq!(tag.blocks.borrow()[&7][..6], [0xFF; 6]);
        assert_eq!(tag.blocks.borrow()[&4], [0; 16]);
        assert_eq!(read(&tag, &uid).unwrap(), None);
    }
}
