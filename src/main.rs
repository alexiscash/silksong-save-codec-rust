use aes::cipher::BlockEncryptMut;
use base64::{engine::general_purpose, Engine as _};
use aes::Aes256;
use ecb::Decryptor;
use ecb::Encryptor;
use block_padding::Pkcs7;
use ecb::cipher::{BlockDecryptMut, KeyInit};

const AES_KEY_STRING: &str = "UKu52ePUBwetZ9wNX88o54dnfKRu0T1l";
const CSHARP_HEADER: [u8; 22] = [0, 1, 0, 0, 0, 255, 255, 255,
                       255, 1, 0, 0, 0, 0, 0, 0, 0, 6, 1, 0, 0, 0];

fn decrypt(payload: Vec<u8>) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let without_header = &payload[CSHARP_HEADER.len()..payload.len() - 1];

    let mut len_count = 0;
    for i in 0..5 {
        len_count += 1;
        if (without_header[i] & 0x80) == 0 {
            break;
        }
    }

    let no_header = &without_header[len_count..];
    let mut b64_encrypted = general_purpose::STANDARD.decode(no_header)?;
    let key = AES_KEY_STRING.as_bytes();

    let cipher = Decryptor::<Aes256>::new_from_slice(key)
        .map_err(|e: aes::cipher::InvalidLength| format!("Invalid key length: {:?}",e))?;

    let decrypted = cipher.decrypt_padded_mut::<Pkcs7>(&mut b64_encrypted)
        .map_err(|e: block_padding::UnpadError| format!("Unpad error: {:?}", e))?;

    let text = std::str::from_utf8(decrypted)?.to_string();
    let json: serde_json::Value = serde_json::from_str(&text)?;

    Ok(json)
}

fn encrypt(json_obj: serde_json::Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut json_bytes = serde_json::to_string(&json_obj)?.into_bytes();

    let cipher = Encryptor::<Aes256>::new_from_slice(AES_KEY_STRING.as_bytes())
        .map_err(|e: aes::cipher::InvalidLength| format!("Invalid key length: {:?}",e))?;

    let block_size = 16;
    let msg_size = json_bytes.len();
    let padded_len = ((msg_size / block_size) + 1) * block_size;

    json_bytes.resize(padded_len, 0u8);

    let encrypted = cipher.encrypt_padded_mut::<Pkcs7>(&mut json_bytes, msg_size)
        .map_err(|e| format!("Padding error: {:?}", e))?;

    let b64_bytes = general_purpose::STANDARD.encode(encrypted).into_bytes();

    let mut out = Vec::<u8>::new();

    let mut n = b64_bytes.len();
    loop {
        let byte = n & 0x7f;
        n >>= 7;
        if n > 0 {
            out.push(byte as u8 | 0x80);
        } else {
            out.push(byte as u8);
            break;
        }
    }

    let mut final_bytes = Vec::<u8>::new();

    final_bytes.extend_from_slice(&CSHARP_HEADER);
    final_bytes.append(&mut out);
    final_bytes.extend_from_slice(&b64_bytes);

    Ok(final_bytes)
}

// fn save_json(obj: serde_json::Value, path: &str) -> Result<(), Box<dyn std::error::Error>>{
//     let pretty = serde_json::to_string_pretty(&obj)?;
//     std::fs::write(path, &pretty)?;
//     Ok(())
// }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::fs::read("saves/user2.dat")?;
    let json = decrypt(raw)?;
    let encrypted = encrypt(json.clone())?;
    let decrypted = decrypt(encrypted)?;
    assert_eq!(json, decrypted);

    // let json_obj = serde_json::from_reader(rdr)
    

    Ok(())
}